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
        self._tracked_assets={}
        self._tracked_findings={}
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
                items=[Asset.model_validate(self._payload(row)) for row in cur.fetchall()]
        for item in items:
            self._tracked_assets[(item.tenant_id,item.id)]=item
        return items+[
            item for item in self._pending_assets
            if (item.tenant_id,item.id) not in self._tracked_assets
        ]

    def all_findings(self):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload_json FROM findings ORDER BY tenant_id,id")
                items=[Finding.model_validate(self._payload(row)) for row in cur.fetchall()]
        for item in items:
            self._tracked_findings[(item.tenant_id,item.id)]=item
        return items+[
            item for item in self._pending_findings
            if (item.tenant_id,item.id) not in self._tracked_findings
        ]

    def list_assets(self, tenant_id: str):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json FROM assets WHERE tenant_id=%s ORDER BY id",
                    (tenant_id,),
                )
                items=[Asset.model_validate(self._payload(row)) for row in cur.fetchall()]
        for item in items:
            self._tracked_assets[(item.tenant_id,item.id)]=item
        return items+[
            item for item in self._pending_assets
            if item.tenant_id==tenant_id
            and (item.tenant_id,item.id) not in self._tracked_assets
        ]

    def list_findings(self, tenant_id: str, asset_ids: Iterable[str] | None=None):
        allowed=None if asset_ids is None else tuple(asset_ids)
        with self._connection() as conn:
            with conn.cursor() as cur:
                if allowed is None:
                    cur.execute(
                        "SELECT payload_json FROM findings WHERE tenant_id=%s ORDER BY id",
                        (tenant_id,),
                    )
                else:
                    if not allowed:
                        return []
                    cur.execute(
                        "SELECT payload_json FROM findings "
                        "WHERE tenant_id=%s AND asset_id = ANY(%s) ORDER BY id",
                        (tenant_id,list(allowed)),
                    )
                items=[Finding.model_validate(self._payload(row)) for row in cur.fetchall()]
        for item in items:
            self._tracked_findings[(item.tenant_id,item.id)]=item
        return items+[
            item for item in self._pending_findings
            if item.tenant_id==tenant_id
            and (allowed is None or item.asset_id in allowed)
            and (item.tenant_id,item.id) not in self._tracked_findings
        ]

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
        if not row:
            return next(
                (
                    item for item in self._pending_findings
                    if item.tenant_id==tenant_id and item.id==finding_id
                ),
                None,
            )
        item=Finding.model_validate(self._payload(row))
        self._tracked_findings[(item.tenant_id,item.id)]=item
        return item

    def add_asset(self, asset: Asset) -> Asset:
        self._pending_assets.append(asset)
        return asset

    def add_finding(self, finding: Finding) -> Finding:
        self._pending_findings.append(finding)
        return finding

    def persist(self) -> None:
        assets={
            **self._tracked_assets,
            **{(item.tenant_id,item.id):item for item in self._pending_assets},
        }
        findings={
            **self._tracked_findings,
            **{(item.tenant_id,item.id):item for item in self._pending_findings},
        }
        if not assets and not findings:
            return
        with self._connection() as conn:
            with conn.cursor() as cur:
                for asset in assets.values():
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
                for finding in findings.values():
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
        self._tracked_assets.clear()
        self._tracked_findings.clear()

    def tenant_record_counts(self, tenant_id: str) -> dict[str,int]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM assets WHERE tenant_id=%s",(tenant_id,))
                assets=int(cur.fetchone()[0])
                cur.execute("SELECT COUNT(*) FROM findings WHERE tenant_id=%s",(tenant_id,))
                findings=int(cur.fetchone()[0])
        return {"assets":assets,"findings":findings}

    def purge_tenant(self, tenant_id: str) -> dict[str,int]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM findings WHERE tenant_id=%s",(tenant_id,))
                findings=max(0,int(cur.rowcount))
                cur.execute("DELETE FROM assets WHERE tenant_id=%s",(tenant_id,))
                assets=max(0,int(cur.rowcount))
        self._pending_assets=[item for item in self._pending_assets if item.tenant_id!=tenant_id]
        self._pending_findings=[item for item in self._pending_findings if item.tenant_id!=tenant_id]
        self._tracked_assets={key:item for key,item in self._tracked_assets.items() if key[0]!=tenant_id}
        self._tracked_findings={key:item for key,item in self._tracked_findings.items() if key[0]!=tenant_id}
        return {"assets":assets,"findings":findings}
