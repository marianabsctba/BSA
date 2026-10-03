from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from .postgres_pool import pooled_connection


def _is_production() -> bool:
    return os.getenv("BSA_ENV", "development").strip().lower() in {"production", "prod"}


def _allow_legacy() -> bool:
    return os.getenv("BSA_ALLOW_LEGACY_STORAGE", "0").strip().lower() in {"1", "true", "yes", "on"}


class SQLiteDigitalRiskRepository:
    def __init__(self, path: str | None = None):
        self.path = path or os.getenv("BSA_DRP_DB", "").strip() or os.getenv(
            "BSA_AUTH_DB", str(Path("/tmp") / "bsa_auth.db")
        )

    def _connection(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS digital_risk(
              event_id TEXT NOT NULL, tenant_id TEXT NOT NULL, payload TEXT NOT NULL,
              created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
              PRIMARY KEY(tenant_id,event_id))"""
        )
        info = conn.execute("PRAGMA table_info(digital_risk)").fetchall()
        pk = [r["name"] for r in sorted((r for r in info if r["pk"]), key=lambda r: r["pk"])]
        if pk == ["event_id"]:
            conn.execute(
                """CREATE TABLE digital_risk_v2(
                  event_id TEXT NOT NULL, tenant_id TEXT NOT NULL, payload TEXT NOT NULL,
                  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                  PRIMARY KEY(tenant_id,event_id))"""
            )
            conn.execute(
                """INSERT INTO digital_risk_v2(event_id,tenant_id,payload,created_at,updated_at)
                SELECT event_id,tenant_id,payload,created_at,updated_at FROM digital_risk"""
            )
            conn.execute("DROP TABLE digital_risk")
            conn.execute("ALTER TABLE digital_risk_v2 RENAME TO digital_risk")
        conn.commit()
        return conn

    def list(self, tenant_id: str, category: str | None = None) -> list[dict]:
        conn = self._connection()
        try:
            query = "SELECT payload FROM digital_risk WHERE tenant_id=?"
            args: list[object] = [tenant_id]
            if category:
                query += " AND json_extract(payload,'$.category')=?"
                args.append(category)
            rows = conn.execute(query + " ORDER BY updated_at DESC", args).fetchall()
            return [json.loads(row["payload"]) for row in rows]
        finally:
            conn.close()

    def get(self, tenant_id: str, event_id: str) -> tuple[dict, int] | None:
        conn = self._connection()
        try:
            row = conn.execute(
                "SELECT payload,created_at FROM digital_risk WHERE tenant_id=? AND event_id=?",
                (tenant_id, event_id),
            ).fetchone()
            if not row:
                return None
            return json.loads(row["payload"]), int(row["created_at"])
        finally:
            conn.close()

    def put(self, tenant_id: str, event_id: str, payload: dict, created_at: int, updated_at: int) -> None:
        conn = self._connection()
        try:
            conn.execute(
                """INSERT INTO digital_risk(event_id,tenant_id,payload,created_at,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,event_id) DO UPDATE SET
                payload=excluded.payload,updated_at=excluded.updated_at""",
                (event_id, tenant_id, json.dumps(payload, ensure_ascii=False), created_at, updated_at),
            )
            conn.commit()
        finally:
            conn.close()


class PostgresDigitalRiskRepository:
    def __init__(self, dsn: str, *, connect=None, bootstrap: bool = False):
        if not str(dsn or "").strip():
            raise ValueError("PostgreSQL DSN is required")
        self._dsn = dsn
        self._connect = connect or pooled_connection
        if bootstrap:
            self.ensure_schema()
        else:
            self.verify_schema()

    def _connection(self):
        return self._connect(self._dsn)

    def ensure_schema(self) -> None:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS digital_risk(
                      tenant_id TEXT NOT NULL,
                      event_id TEXT NOT NULL,
                      payload_json JSONB NOT NULL,
                      created_at BIGINT NOT NULL,
                      updated_at BIGINT NOT NULL,
                      PRIMARY KEY(tenant_id,event_id))"""
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_digital_risk_tenant_updated "
                    "ON digital_risk(tenant_id,updated_at DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_digital_risk_category "
                    "ON digital_risk(tenant_id,((payload_json->>'category')))"
                )

    def verify_schema(self) -> None:
        try:
            with self._connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT tenant_id,event_id FROM digital_risk LIMIT 1")
        except Exception as exc:
            raise RuntimeError(
                "PostgreSQL DRP schema is not ready; run the DRP storage bootstrap/migration first"
            ) from exc

    @staticmethod
    def _payload(value) -> dict:
        return value if isinstance(value, dict) else json.loads(value)

    def list(self, tenant_id: str, category: str | None = None) -> list[dict]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                if category:
                    cur.execute(
                        "SELECT payload_json FROM digital_risk "
                        "WHERE tenant_id=%s AND payload_json->>'category'=%s "
                        "ORDER BY updated_at DESC",
                        (tenant_id, category),
                    )
                else:
                    cur.execute(
                        "SELECT payload_json FROM digital_risk WHERE tenant_id=%s ORDER BY updated_at DESC",
                        (tenant_id,),
                    )
                return [self._payload(row[0]) for row in cur.fetchall()]

    def get(self, tenant_id: str, event_id: str) -> tuple[dict, int] | None:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json,created_at FROM digital_risk WHERE tenant_id=%s AND event_id=%s",
                    (tenant_id, event_id),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return self._payload(row[0]), int(row[1])

    def put(self, tenant_id: str, event_id: str, payload: dict, created_at: int, updated_at: int) -> None:
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO digital_risk(tenant_id,event_id,payload_json,created_at,updated_at)
                    VALUES(%s,%s,%s::jsonb,%s,%s)
                    ON CONFLICT(tenant_id,event_id) DO UPDATE SET
                    payload_json=excluded.payload_json,updated_at=excluded.updated_at""",
                    (tenant_id, event_id, serialized, created_at, updated_at),
                )


def digital_risk_repository(*, sqlite_path: str | None = None):
    backend = os.getenv(
        "BSA_DRP_REPOSITORY_BACKEND",
        "postgres" if _is_production() else "sqlite",
    ).strip().lower()

    if backend in {"sqlite", "legacy"}:
        if _is_production() and not _allow_legacy():
            raise RuntimeError(
                "legacy DRP storage is disabled in production; configure PostgreSQL or explicitly set BSA_ALLOW_LEGACY_STORAGE=1 for emergency rollback"
            )
        return SQLiteDigitalRiskRepository(path=sqlite_path)

    if backend == "postgres":
        dsn = os.getenv("BSA_DATABASE_URL", "").strip()
        if not dsn:
            raise RuntimeError(
                "BSA_DATABASE_URL is required when BSA_DRP_REPOSITORY_BACKEND=postgres"
            )
        return PostgresDigitalRiskRepository(dsn)

    raise RuntimeError(f"unsupported DRP repository backend: {backend}")
