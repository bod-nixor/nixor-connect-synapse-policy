#!/usr/bin/env python3
"""Fail closed if a Synapse deployment config is not production-shaped."""

import argparse
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "modules"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        config = yaml.safe_load(arguments.config.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("root configuration must be a mapping")
        database = config.get("database")
        if not isinstance(database, dict) or database.get("name") != "psycopg2":
            raise ValueError("production Synapse database must use psycopg2")
        if config.get("enable_registration") is not False:
            raise ValueError("public registration must be disabled")
        if not isinstance(config.get("password_config"), dict) or config["password_config"].get("enabled") is not False:
            raise ValueError("local password login must be disabled")
        modules = config.get("modules")
        if not isinstance(modules, list):
            raise ValueError("modules must be configured")
        module = next((entry for entry in modules if isinstance(entry, dict) and entry.get("module") == "nixor_policy_checker.NixorPolicyChecker"), None)
        if module is None or not isinstance(module.get("config"), dict):
            raise ValueError("NixorPolicyChecker module is missing")
        from nixor_policy_checker import NixorPolicyChecker
        NixorPolicyChecker.parse_config(module["config"])
        print("Synapse production configuration passed PostgreSQL, login, and fail-closed policy checks")
        return 0
    except Exception as error:
        print(f"Synapse production configuration rejected: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
