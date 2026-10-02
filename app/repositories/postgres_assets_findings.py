from __future__ import annotations

import json
from collections.abc import Iterable

from ..application.ports.asset_finding_repository import AssetFindingRepositoryPort
from ..models import Asset, Finding


class PostgresAssetFindingRepository(AssetFindingRepositoryPort):
    """PostgreSQL-backed asset/finding repository.

    Connections are short-lived and transaction-scoped so API and worker
    replicas can share the same durable state safely.
    """

    def __init__(self, dsn: str, connect=None):
        if not str(dsn or "").strip():
            raise ValueError("PostgreSQL DSN is required")
        self._dsn=dsn
        self._connect=connect or self._default_connect
        self._pending_assets=[]
        self._pending_findings=[]
        self._ensure_schema()

    @staticmethod
    def _default_connect(dsn: str):
        import psycopg
        return psycopg.connect(dsn)

    def _connection(self):
        return self._connect(self._dsn)

    def _ensure_schema(self) -> None:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS assets(
                        tenant_id TEXT NOT NULL,
                        id TEXT NOT NULL,
                        payload_json JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY(tenant_id,id)
                    )"""
                )
                cur.execute(
                    """CREATE TABLE IF NOT EXISTS findings(
                        tenant_id TEXT NOT NULL,
                        id TEXT NOT NULL,
                        asset_id TEXT NOT NULL,
                        payload_json JSONB NOT NULL,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        PRIMARY KEY(tenant_id,id)
                    )"""
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_findings_tenant_asset "
                    "ON findings(tenant_id,asset_id)"
                )

    @staticmethod
    def _payload(row):
        value=row[0] if not isinstance(row,dict) else row["payload_json"]
        return value if isinstance(value,dict) else json.loads(value)

    def all_assets(self):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload_json FROM assets ORDER BY tenant_id,id")
                return [Asset.model_validate(self._payload(row)) for row in cur.fetchall()]

    def all_findings(self):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload_json FROM findings ORDER BY tenant_id,id")
                return [Finding.model_validate(self._payload(row)) for row in cur.fetchall()]

    def list_assets(self, tenant_id: str):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json FROM assets WHERE tenant_id=%s ORDER BY id",
                    (tenant_id,),
                )
                return [Asset.model_validate(self._payload(row)) for row in cur.fetchall()]

    def list_findings(self, tenant_id: str, asset_ids: Iterable[str] | None=None):
        with self._connection() as conn:
            with conn.cursor() as cur:
                if asset_ids is None:
                    cur.execute(
                        "SELECT payload_json FROM findings WHERE tenant_id=%s ORDER BY id",
                        (tenant_id,),
                    )
                else:
                    ids=tuple(asset_ids)
                    if not ids:
                        return []
                    cur.execute(
                        "SELECT payload_json FROM findings "
                        "WHERE tenant_id=%s AND asset_id = ANY(%s) ORDER BY id",
                        (tenant_id,list(ids)),
                    )
                return [Finding.model_validate(self._payload(row)) for row in cur.fetchall()]

    def find_asset_by_value(self, tenant_id: str, value: str):
        wanted=str(value or "").strip().lower()
        return next(
            (
                asset for asset in self.list_assets(tenant_id)
                if str(asset.value).strip().lower()==wanted
            ),
            None,
        )

    def find_finding(self, tenant_id: str, finding_id: str):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json FROM findings WHERE tenant_id=%s AND id=%s",
                    (tenant_id,finding_id),
                )
                row=cur.fetchone()
                return Finding.model_validate(self._payload(row)) if row else None

    def add_asset(self, asset: Asset) -> Asset:
        self._pending_assets.append(asset)
        return asset

    def add_finding(self, finding: Finding) -> Finding:
        self._pending_findings.append(finding)
        return finding

    def persist(self) -> None:
        if not self._pending_assets and not self._pending_findings:
            return
        with self._connection() as conn:
            with conn.cursor() as cur:
                for asset in self._pending_assets:
                    cur.execute(
                        """INSERT INTO assets(tenant_id,id,payload_json,updated_at)
                           VALUES(%s,%s,%s::jsonb,NOW())
                           ON CONFLICT(tenant_id,id) DO UPDATE SET
                             payload_json=EXCLUDED.payload_json,
                             updated_at=NOW()""",
                        (
                            asset.tenant_id,
                            asset.id,
                            json.dumps(asset.model_dump(mode="json"),ensure_ascii=False),
                        ),
                    )
                for finding in self._pending_findings:
                    cur.execute(
                        """INSERT INTO findings(tenant_id,id,asset_id,payload_json,updated_at)
                           VALUES(%s,%s,%s,%s::jsonb,NOW())
                           ON CONFLICT(tenant_id,id) DO UPDATE SET
                             asset_id=EXCLUDED.asset_id,
                             payload_json=EXCLUDED.payload_json,
                             updated_at=NOW()""",
                        (
                            finding.tenant_id,
                            finding.id,
                            finding.asset_id,
                            json.dumps(finding.model_dump(mode="json"),ensure_ascii=False),
                        ),
                    )
        self._pending_assets.clear()
        self._pending_findings.clear()
