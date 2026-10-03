"""Controlled migration of DRP events from SQLite to PostgreSQL."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path

from .repositories.digital_risk_events import PostgresDigitalRiskRepository


def load_sqlite_events(path: str | Path) -> list[tuple[str, str, dict, int, int]]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"SQLite DRP store not found: {source}")
    conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        check = conn.execute("PRAGMA integrity_check").fetchone()
        if not check or str(check[0]).lower() != "ok":
            raise RuntimeError("SQLite integrity check failed")
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='digital_risk'"
        ).fetchone()
        if not table:
            return []
        rows = conn.execute(
            "SELECT tenant_id,event_id,payload,created_at,updated_at FROM digital_risk "
            "ORDER BY tenant_id,event_id"
        ).fetchall()
        return [
            (
                str(row["tenant_id"]),
                str(row["event_id"]),
                json.loads(row["payload"]),
                int(row["created_at"]),
                int(row["updated_at"]),
            )
            for row in rows
        ]
    finally:
        conn.close()


def migrate_events(events, destination, *, dry_run: bool = False) -> dict:
    source_keys = {(tenant_id, event_id) for tenant_id, event_id, *_ in events}
    tenants = sorted({tenant_id for tenant_id, *_ in events})
    if dry_run:
        return {
            "status": "validated",
            "dry_run": True,
            "events": len(events),
            "tenants": tenants,
        }

    for tenant_id, event_id, payload, created_at, updated_at in events:
        destination.put(tenant_id, event_id, payload, created_at, updated_at)

    migrated_keys = {
        (tenant_id, str(item.get("event_id") or ""))
        for tenant_id in tenants
        for item in destination.list(tenant_id)
    }
    missing = sorted(source_keys - migrated_keys)
    if missing:
        raise RuntimeError(f"PostgreSQL DRP reconciliation failed: {len(missing)} event(s) missing")

    return {
        "status": "migrated",
        "dry_run": False,
        "events": len(events),
        "tenants": tenants,
        "verified": len(source_keys),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m app.migrate_digital_risk",
        description="Migrate BSA DRP events from SQLite to PostgreSQL.",
    )
    parser.add_argument(
        "--sqlite",
        default=os.getenv("BSA_DRP_DB", "").strip()
        or os.getenv("BSA_AUTH_DB", "/data/bsa_auth.db"),
        help="source SQLite DRP store",
    )
    parser.add_argument(
        "--dsn",
        default=os.getenv("BSA_DATABASE_URL", ""),
        help="destination PostgreSQL DSN",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.dsn:
        raise SystemExit("BSA_DATABASE_URL or --dsn is required")

    events = load_sqlite_events(args.sqlite)
    destination = PostgresDigitalRiskRepository(args.dsn, bootstrap=True)
    result = migrate_events(events, destination, dry_run=args.dry_run)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
