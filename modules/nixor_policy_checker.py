import ipaddress
import logging
import re
import uuid
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from synapse.module_api import NOT_SPAM, ModuleApi

try:
    from synapse.module_api.errors import Codes, ConfigError
except ImportError:  # Compatibility with older supported Synapse releases.
    from synapse.api.errors import Codes
    from synapse.config import ConfigError


logger = logging.getLogger(__name__)

_MATRIX_ROOM_ID = re.compile(r"^![^:\s]{1,255}:[^\s]{1,255}$")
_VISIBLE_ASCII_SECRET = re.compile(r"^[\x21-\x7e]{32,512}$")
_POLICY_PATH = "/internal/policy/check"
_MAX_INITIAL_STATE_EVENTS = 100
_ALLOWED_CONFIG_KEYS = {
    "governance_api_url",
    "policy_shared_secret",
    "policy_shared_secret_file",
    "fail_closed",
}


class InvalidRoomConfig(ValueError):
    pass


def _is_private_http_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized in {"localhost", "host.docker.internal"}:
        return True
    if normalized.endswith((".internal", ".localhost")) or "." not in normalized:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _validate_policy_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2_048:
        raise ConfigError("governance_api_url must be a non-empty HTTP(S) URL")
    url = value.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError("governance_api_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError("governance_api_url must not contain credentials, query parameters, or a fragment")
    if parsed.path.rstrip("/") != _POLICY_PATH:
        raise ConfigError(f"governance_api_url must target {_POLICY_PATH}")
    if parsed.scheme == "http" and not _is_private_http_host(parsed.hostname):
        raise ConfigError("unencrypted governance_api_url is allowed only for private or loopback hosts")
    return url.rstrip("/")


def _validate_secret(value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigError("policy shared secret must be a string")
    secret = value.strip()
    if not _VISIBLE_ASCII_SECRET.fullmatch(secret):
        raise ConfigError("policy shared secret must contain 32-512 visible ASCII characters")
    return secret


def _read_secret_file(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("policy_shared_secret_file must be an absolute path")
    path = Path(value.strip())
    if not path.is_absolute():
        raise ConfigError("policy_shared_secret_file must be an absolute path")
    try:
        if not path.is_file() or path.stat().st_size > 4_096:
            raise ConfigError("policy_shared_secret_file must be a readable regular file no larger than 4096 bytes")
        return _validate_secret(path.read_text(encoding="utf-8"))
    except ConfigError:
        raise
    except OSError as error:
        raise ConfigError("policy_shared_secret_file could not be read") from error


class NixorPolicyChecker:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.governance_api_url = config["governance_api_url"]
        self.policy_shared_secret = config["policy_shared_secret"]

        self.api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )
        # Keep the third-party rule as defense in depth for Synapse versions and
        # event paths that invoke the two callback families differently.
        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed,
        )

        logger.info("NixorPolicyChecker loaded with fail-closed governance checks")

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(config, dict):
            raise ConfigError("NixorPolicyChecker config must be a mapping")
        unknown = sorted(set(config) - _ALLOWED_CONFIG_KEYS)
        if unknown:
            raise ConfigError(f"unknown NixorPolicyChecker config key: {unknown[0]}")
        if config.get("fail_closed", True) is not True:
            raise ConfigError("fail_closed must be true")

        direct_secret = config.get("policy_shared_secret")
        secret_file = config.get("policy_shared_secret_file")
        if (direct_secret is None) == (secret_file is None):
            raise ConfigError("configure exactly one of policy_shared_secret or policy_shared_secret_file")
        secret = _validate_secret(direct_secret) if direct_secret is not None else _read_secret_file(secret_file)

        return {
            "governance_api_url": _validate_policy_url(config.get("governance_api_url")),
            "policy_shared_secret": secret,
            "fail_closed": True,
        }

    @staticmethod
    def _initial_state(room_config: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        initial_state = room_config.get("initial_state", [])
        if initial_state is None:
            return []
        if not isinstance(initial_state, list) or len(initial_state) > _MAX_INITIAL_STATE_EVENTS:
            raise InvalidRoomConfig("invalid initial_state")
        if any(not isinstance(event, Mapping) for event in initial_state):
            raise InvalidRoomConfig("invalid initial_state event")
        return initial_state

    @classmethod
    def _room_config_requests_encryption(cls, room_config: Mapping[str, Any]) -> bool:
        return any(event.get("type") == "m.room.encryption" for event in cls._initial_state(room_config))

    @classmethod
    def _extract_parent_space_id(cls, room_config: Mapping[str, Any]) -> Optional[str]:
        creation_content = room_config.get("creation_content", {})
        if creation_content is None:
            creation_content = {}
        if not isinstance(creation_content, Mapping):
            raise InvalidRoomConfig("invalid creation_content")

        declared_parent = creation_content.get("io.nixor.parent_space_id")
        if declared_parent is not None and (
            not isinstance(declared_parent, str) or not _MATRIX_ROOM_ID.fullmatch(declared_parent)
        ):
            raise InvalidRoomConfig("invalid declared parent space")

        parent_events = [event for event in cls._initial_state(room_config) if event.get("type") == "m.space.parent"]
        if len(parent_events) > 1:
            raise InvalidRoomConfig("multiple parent spaces are not allowed at creation")
        if not parent_events:
            if declared_parent is not None:
                raise InvalidRoomConfig("declared parent space requires matching m.space.parent state")
            return None

        parent_event = parent_events[0]
        state_key = parent_event.get("state_key")
        content = parent_event.get("content")
        if not isinstance(state_key, str) or not _MATRIX_ROOM_ID.fullmatch(state_key):
            raise InvalidRoomConfig("invalid m.space.parent state key")
        if declared_parent is not None and declared_parent != state_key:
            raise InvalidRoomConfig("parent space declarations do not match")
        if not isinstance(content, Mapping) or content.get("canonical") is not True:
            raise InvalidRoomConfig("m.space.parent must be canonical")
        via = content.get("via")
        if (
            not isinstance(via, list)
            or not 1 <= len(via) <= 10
            or any(not isinstance(server, str) or not server or len(server) > 255 for server in via)
        ):
            raise InvalidRoomConfig("m.space.parent must contain bounded via servers")
        return state_key

    @classmethod
    def _classify_creation(cls, room_config: Mapping[str, Any]) -> Tuple[str, str, Optional[str]]:
        creation_content = room_config.get("creation_content", {})
        if creation_content is None:
            creation_content = {}
        if not isinstance(creation_content, Mapping):
            raise InvalidRoomConfig("invalid creation_content")
        room_type = creation_content.get("type")
        if room_type not in {None, "m.space"}:
            raise InvalidRoomConfig("unsupported room type")

        parent_space_id = cls._extract_parent_space_id(room_config)
        if room_type == "m.space":
            return ("create_subspace" if parent_space_id else "create_space", "space", parent_space_id)
        return ("create_room_in_space" if parent_space_id else "create_room", "room", parent_space_id)

    async def check_event_allowed(self, event: Any, state_events: Any) -> Tuple[bool, None]:
        del state_events
        if getattr(event, "type", None) == "m.room.encryption":
            logger.warning(
                "Blocked m.room.encryption through third-party rules room=%s sender=%s",
                getattr(event, "room_id", None),
                getattr(event, "sender", None),
            )
            return False, None
        return True, None

    async def user_may_create_room(
        self,
        user_id: str,
        room_config: Optional[Dict[str, Any]] = None,
    ) -> Any:
        if not isinstance(user_id, str) or not user_id.startswith("@") or ":" not in user_id or len(user_id) > 512:
            logger.warning("Denied room creation with malformed Matrix user ID")
            return Codes.FORBIDDEN
        if room_config is None:
            room_config = {}
        if not isinstance(room_config, Mapping):
            logger.warning("Denied room creation with malformed room config user=%s", user_id)
            return Codes.FORBIDDEN

        try:
            if self._room_config_requests_encryption(room_config):
                logger.warning("Denied encrypted room creation user=%s", user_id)
                return Codes.FORBIDDEN
            action, normalized_room_type, parent_space_id = self._classify_creation(room_config)
        except InvalidRoomConfig as error:
            logger.warning("Denied malformed governed room creation user=%s reason=%s", user_id, str(error))
            return Codes.FORBIDDEN

        allowed = await self._check_governance_policy(
            matrix_user_id=user_id,
            action=action,
            room_type=normalized_room_type,
            parent_space_id=parent_space_id,
        )
        if allowed:
            return NOT_SPAM

        logger.warning(
            "Denied governed creation action=%s user=%s parent_space_id=%s",
            action,
            user_id,
            parent_space_id,
        )
        return Codes.FORBIDDEN

    async def _check_governance_policy(
        self,
        matrix_user_id: str,
        action: str,
        room_type: str,
        parent_space_id: Optional[str],
    ) -> bool:
        correlation_id = f"synapse-policy:{uuid.uuid4().hex}"
        payload = {
            "matrix_user_id": matrix_user_id,
            "action": action,
            "room_type": room_type,
            "parent_space_id": parent_space_id,
        }
        headers = {
            b"Authorization": [f"Bearer {self.policy_shared_secret}".encode("ascii")],
            b"X-Correlation-ID": [correlation_id.encode("ascii")],
        }
        try:
            body = await self.api.http_client.post_json_get_json(
                uri=self.governance_api_url,
                post_json=payload,
                headers=headers,
            )
        except Exception as error:
            logger.error(
                "Governance policy request failed closed action=%s correlation_id=%s error_type=%s",
                action,
                correlation_id,
                type(error).__name__,
            )
            return False

        if not isinstance(body, dict) or type(body.get("allowed")) is not bool:
            logger.error(
                "Governance policy response failed schema validation action=%s correlation_id=%s",
                action,
                correlation_id,
            )
            return False
        reason = body.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1_000:
            logger.error(
                "Governance policy response omitted a valid reason action=%s correlation_id=%s",
                action,
                correlation_id,
            )
            return False
        return body["allowed"] is True

    async def check_event_for_spam(self, event: Any) -> Any:
        if getattr(event, "type", None) == "m.room.encryption":
            logger.warning(
                "Blocked m.room.encryption event room=%s sender=%s",
                getattr(event, "room_id", None),
                getattr(event, "sender", None),
            )
            return Codes.FORBIDDEN
        return NOT_SPAM
