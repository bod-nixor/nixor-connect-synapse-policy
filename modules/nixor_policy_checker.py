import json
import logging
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from synapse.module_api import NOT_SPAM, ModuleApi

try:
    from synapse.module_api.errors import Codes
except Exception:
    from synapse.api.errors import Codes


logger = logging.getLogger(__name__)


class NixorPolicyChecker:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.panapticon_api_url = config.get(
            "panapticon_api_url",
            "http://host.docker.internal:4000/internal/policy/check",
        )
        self.policy_shared_secret = config.get("policy_shared_secret", "")
        self.fail_closed = bool(config.get("fail_closed", True))

        self.api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )

        self.api.register_third_party_rules_callbacks(
            check_event_allowed=self.check_event_allowed,
        )

        logger.info("NixorPolicyChecker loaded")

    @staticmethod
    def parse_config(config: Dict[str, Any]) -> Dict[str, Any]:
        return config
    
    def _room_config_requests_encryption(self, room_config: Dict[str, Any]) -> bool:
        initial_state = room_config.get("initial_state") or []

        for event in initial_state:
            if event.get("type") == "m.room.encryption":
                return True

        return False
    
    async def check_event_allowed(self, event, state_events):
        if getattr(event, "type", None) == "m.room.encryption":
            logger.warning(
                "NixorPolicyChecker blocked m.room.encryption through third-party rules room=%s sender=%s",
                getattr(event, "room_id", None),
                getattr(event, "sender", None),
            )
            return False, None

        return True, None

    async def user_may_create_room(self, user_id: str, room_config: Optional[Dict[str, Any]] = None):
        room_config = room_config or {}

        if self._room_config_requests_encryption(room_config):
            logger.warning("NixorPolicyChecker denied encrypted room creation for %s", user_id)
            return Codes.FORBIDDEN

        creation_content = room_config.get("creation_content") or {}
        room_type = creation_content.get("type")

        parent_space_id = self._extract_parent_space_id(room_config)

        if room_type == "m.space":
            action = "create_subspace" if parent_space_id else "create_space"
            normalized_room_type = "space"
        elif parent_space_id:
            action = "create_room_in_space"
            normalized_room_type = "room"
        else:
            action = "create_room"
            normalized_room_type = "room"

        allowed = self._check_panapticon_policy(
            matrix_user_id=user_id,
            action=action,
            room_type=normalized_room_type,
            parent_space_id=parent_space_id,
        )

        if allowed:
            return NOT_SPAM

        logger.warning(
            "NixorPolicyChecker denied %s for %s parent_space_id=%s",
            action,
            user_id,
            parent_space_id,
        )
        return Codes.FORBIDDEN

    def _extract_parent_space_id(self, room_config: Dict[str, Any]) -> Optional[str]:
        creation_content = room_config.get("creation_content") or {}

        nixor_parent_space_id = creation_content.get("io.nixor.parent_space_id")
        if nixor_parent_space_id:
            return nixor_parent_space_id

        initial_state = room_config.get("initial_state") or []

        for event in initial_state:
            if event.get("type") == "m.space.parent":
                state_key = event.get("state_key")
                if state_key:
                    return state_key

        return None

    def _check_panapticon_policy(
        self,
        matrix_user_id: str,
        action: str,
        room_type: str,
        parent_space_id: Optional[str],
    ) -> bool:
        payload = {
            "matrix_user_id": matrix_user_id,
            "action": action,
            "room_type": room_type,
            "parent_space_id": parent_space_id,
        }

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            self.panapticon_api_url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.policy_shared_secret}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                body = json.loads(response.read().decode("utf-8"))
                return bool(body.get("allowed"))
        except urllib.error.HTTPError as e:
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                error_body = ""

            logger.warning(
                "Panapticon API denied policy check status=%s body=%s payload=%s",
                e.code,
                error_body,
                payload,
            )
            return False
        except Exception:
            logger.exception("Panapticon API policy check failed payload=%s", payload)
            return not self.fail_closed
        
    async def check_event_for_spam(self, event):
        if getattr(event, "type", None) == "m.room.encryption":
            logger.warning(
                "NixorPolicyChecker blocked m.room.encryption event in room=%s sender=%s",
                getattr(event, "room_id", None),
                getattr(event, "sender", None),
            )
            return Codes.FORBIDDEN

        return NOT_SPAM