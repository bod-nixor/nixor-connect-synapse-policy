import asyncio
import importlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


try:
    import synapse.module_api  # type: ignore[import-not-found]
except ModuleNotFoundError:
    synapse = types.ModuleType("synapse")
    module_api = types.ModuleType("synapse.module_api")
    module_errors = types.ModuleType("synapse.module_api.errors")

    class ConfigError(Exception):
        pass

    class Codes:
        FORBIDDEN = "M_FORBIDDEN"

    module_api.NOT_SPAM = object()
    module_api.ModuleApi = object
    module_errors.Codes = Codes
    module_errors.ConfigError = ConfigError
    synapse.module_api = module_api
    sys.modules["synapse"] = synapse
    sys.modules["synapse.module_api"] = module_api
    sys.modules["synapse.module_api.errors"] = module_errors


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "modules"))
policy = importlib.import_module("nixor_policy_checker")


SECRET = "synthetic-policy-secret-at-least-32-bytes"


class FakeHttpClient:
    def __init__(self, response=None, error=None):
        self.response = response if response is not None else {"allowed": True, "reason": "synthetic allow"}
        self.error = error
        self.calls = []

    async def post_json_get_json(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class FakeApi:
    def __init__(self, http_client=None):
        self.http_client = http_client or FakeHttpClient()
        self.spam_callbacks = {}
        self.rule_callbacks = {}

    def register_spam_checker_callbacks(self, **kwargs):
        self.spam_callbacks = kwargs

    def register_third_party_rules_callbacks(self, **kwargs):
        self.rule_callbacks = kwargs


class Event:
    def __init__(self, event_type):
        self.type = event_type
        self.room_id = "!room:example.test"
        self.sender = "@sender:example.test"


def parsed_config(**overrides):
    config = {
        "governance_api_url": "https://panapticon.internal/internal/policy/check",
        "policy_shared_secret": SECRET,
        "fail_closed": True,
    }
    config.update(overrides)
    return policy.NixorPolicyChecker.parse_config(config)


def parent_event(parent="!space:example.test"):
    return {
        "type": "m.space.parent",
        "state_key": parent,
        "content": {"canonical": True, "via": ["example.test"]},
    }


class PolicyConfigTests(unittest.TestCase):
    def test_valid_config_and_private_http_endpoint(self):
        config = policy.NixorPolicyChecker.parse_config({
            "governance_api_url": "http://panapticon:4000/internal/policy/check",
            "policy_shared_secret": SECRET,
            "fail_closed": True,
        })
        self.assertEqual(config["policy_shared_secret"], SECRET)

    def test_secret_file_is_supported(self):
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(SECRET + "\n")
            secret_path = handle.name
        try:
            config = policy.NixorPolicyChecker.parse_config({
                "governance_api_url": "https://panapticon.internal/internal/policy/check",
                "policy_shared_secret_file": secret_path,
                "fail_closed": True,
            })
            self.assertEqual(config["policy_shared_secret"], SECRET)
        finally:
            os.unlink(secret_path)

    def test_unsafe_or_ambiguous_config_is_rejected(self):
        invalid = [
            {},
            {"governance_api_url": "https://panapticon.internal/internal/policy/check", "policy_shared_secret": "short"},
            {"governance_api_url": "http://public.example.com/internal/policy/check", "policy_shared_secret": SECRET},
            {"governance_api_url": "https://panapticon.internal/wrong", "policy_shared_secret": SECRET},
            {"governance_api_url": "https://panapticon.internal/internal/policy/check?secret=x", "policy_shared_secret": SECRET},
            {"governance_api_url": "https://panapticon.internal/internal/policy/check", "policy_shared_secret": SECRET, "fail_closed": False},
            {"governance_api_url": "https://panapticon.internal/internal/policy/check", "policy_shared_secret": SECRET, "policy_shared_secret_file": "/tmp/secret"},
            {"governance_api_url": "https://panapticon.internal/internal/policy/check", "policy_shared_secret": SECRET, "fail_close": True},
        ]
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(policy.ConfigError):
                policy.NixorPolicyChecker.parse_config(config)


class PolicyCallbackTests(unittest.TestCase):
    def make_checker(self, client=None):
        api = FakeApi(client)
        checker = policy.NixorPolicyChecker(parsed_config(), api)
        self.assertIn("user_may_create_room", api.spam_callbacks)
        self.assertIn("check_event_for_spam", api.spam_callbacks)
        self.assertIn("check_event_allowed", api.rule_callbacks)
        return checker, api

    def test_creation_actions_are_classified_and_authorized(self):
        cases = [
            ({}, "create_room", "room", None),
            ({"creation_content": {"type": "m.space"}}, "create_space", "space", None),
            ({"creation_content": {"io.nixor.parent_space_id": "!space:example.test"}, "initial_state": [parent_event()]}, "create_room_in_space", "room", "!space:example.test"),
            ({"creation_content": {"type": "m.space", "io.nixor.parent_space_id": "!space:example.test"}, "initial_state": [parent_event()]}, "create_subspace", "space", "!space:example.test"),
        ]
        for room_config, action, room_type, parent in cases:
            with self.subTest(action=action):
                checker, api = self.make_checker()
                result = asyncio.run(checker.user_may_create_room("@admin:example.test", room_config))
                self.assertIs(result, policy.NOT_SPAM)
                call = api.http_client.calls[0]
                self.assertEqual(call["post_json"], {
                    "matrix_user_id": "@admin:example.test",
                    "action": action,
                    "room_type": room_type,
                    "parent_space_id": parent,
                })
                self.assertEqual(call["headers"][b"Authorization"], [f"Bearer {SECRET}".encode("ascii")])
                self.assertTrue(call["headers"][b"X-Correlation-ID"][0].startswith(b"synapse-policy:"))

    def test_encrypted_and_malformed_room_creation_is_denied_without_api_call(self):
        cases = [
            {"initial_state": [{"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}]},
            {"creation_content": {"type": "unsupported"}},
            {"creation_content": {"io.nixor.parent_space_id": "!space:example.test"}},
            {"creation_content": {"io.nixor.parent_space_id": "!other:example.test"}, "initial_state": [parent_event()]},
            {"initial_state": [parent_event(), parent_event("!second:example.test")]},
            {"initial_state": [{"type": "m.space.parent", "state_key": "!space:example.test", "content": {"via": ["example.test"]}}]},
        ]
        for room_config in cases:
            with self.subTest(room_config=room_config):
                checker, api = self.make_checker()
                result = asyncio.run(checker.user_may_create_room("@student:example.test", room_config))
                self.assertEqual(result, policy.Codes.FORBIDDEN)
                self.assertEqual(api.http_client.calls, [])

    def test_governance_denial_failure_and_malformed_response_fail_closed(self):
        clients = [
            FakeHttpClient({"allowed": False, "reason": "not authorized"}),
            FakeHttpClient({"allowed": 1, "reason": "invalid boolean"}),
            FakeHttpClient({"allowed": True}),
            FakeHttpClient(error=TimeoutError("synthetic timeout")),
        ]
        for client in clients:
            with self.subTest(response=client.response, error=client.error):
                checker, _api = self.make_checker(client)
                result = asyncio.run(checker.user_may_create_room("@student:example.test", {}))
                self.assertEqual(result, policy.Codes.FORBIDDEN)

    def test_encryption_events_are_blocked_by_both_callback_families(self):
        checker, _api = self.make_checker()
        encrypted = Event("m.room.encryption")
        ordinary = Event("m.room.message")
        self.assertEqual(asyncio.run(checker.check_event_for_spam(encrypted)), policy.Codes.FORBIDDEN)
        self.assertIs(asyncio.run(checker.check_event_for_spam(ordinary)), policy.NOT_SPAM)
        self.assertEqual(asyncio.run(checker.check_event_allowed(encrypted, {})), (False, None))
        self.assertEqual(asyncio.run(checker.check_event_allowed(ordinary, {})), (True, None))


if __name__ == "__main__":
    unittest.main()
