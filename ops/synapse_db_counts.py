#!/usr/bin/env python3
"""Capture or compare security-relevant Synapse row counts without printing credentials."""

import argparse
import datetime as dt
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

import yaml


COUNT_TABLES = ("users", "rooms", "devices", "events", "local_media_repository")
POSTGRES_CONNECTION_KEYS = {
    "database", "user", "password", "host", "port", "sslmode", "passfile", "service", "connect_timeout"
}


def load_database_config(path: Path) -> dict[str, Any]:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("database"), dict):
        raise ValueError("configuration does not contain a database mapping")
    return config["database"]


def capture_sqlite(args: dict[str, Any]) -> tuple[str, dict[str, int]]:
    database = args.get("database")
    if not isinstance(database, str) or not database:
        raise ValueError("SQLite database path is missing")
    connection = sqlite3.connect(f"file:{Path(database).resolve()}?mode=ro", uri=True)
    try:
        schema = connection.execute("SELECT version, upgraded FROM schema_version").fetchone()
        counts = {table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]) for table in COUNT_TABLES}
    finally:
        connection.close()
    return f"{schema[0]}:{schema[1]}", counts


def capture_postgres(args: dict[str, Any]) -> tuple[str, dict[str, int]]:
    try:
        import psycopg2
    except ImportError as error:
        raise RuntimeError("psycopg2 is required in the Synapse virtualenv") from error
    connection_args = {key: value for key, value in args.items() if key in POSTGRES_CONNECTION_KEYS}
    connection_args.setdefault("connect_timeout", 10)
    connection = psycopg2.connect(**connection_args)
    connection.set_session(readonly=True, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT version, upgraded FROM schema_version")
            schema = cursor.fetchone()
            counts = {}
            for table in COUNT_TABLES:
                cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                counts[table] = int(cursor.fetchone()[0])
    finally:
        connection.close()
    return f"{schema[0]}:{schema[1]}", counts


def capture(config_path: Path, sqlite_database: Path | None = None) -> dict[str, Any]:
    database = load_database_config(config_path)
    engine = database.get("name")
    args = database.get("args")
    if not isinstance(args, dict):
        raise ValueError("database.args must be a mapping")
    if engine == "sqlite3":
        if sqlite_database is not None:
            args = {**args, "database": str(sqlite_database)}
        schema, counts = capture_sqlite(args)
    elif engine == "psycopg2":
        schema, counts = capture_postgres(args)
    else:
        raise ValueError("database.name must be sqlite3 or psycopg2")
    return {
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "engine": engine,
        "schema_version": schema,
        "counts": counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--sqlite-database", type=Path, help="Explicit copied SQLite database path")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path, help="Baseline JSON created by this script")
    arguments = parser.parse_args()
    try:
        result = capture(arguments.config, arguments.sqlite_database)
        if arguments.compare:
            baseline = json.loads(arguments.compare.read_text(encoding="utf-8"))
            differences = {
                key: {"baseline": baseline.get("counts", {}).get(key), "current": result["counts"].get(key)}
                for key in COUNT_TABLES
                if baseline.get("counts", {}).get(key) != result["counts"].get(key)
            }
            result["comparison"] = {"ok": not differences, "differences": differences}
        serialized = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if arguments.output:
            arguments.output.write_text(serialized, encoding="utf-8")
        else:
            sys.stdout.write(serialized)
        return 1 if result.get("comparison", {}).get("ok") is False else 0
    except Exception as error:
        print(f"Synapse count capture failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
