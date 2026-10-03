from __future__ import annotations

import json
from collections.abc import Iterable

from ..application.ports.asset_finding_repository import AssetFindingRepositoryPort
from ..models import Asset, Finding
from .postgres_pool import pooled_connection


class ConcurrentUpdateError(RuntimeError):
    """Raised when a tracked PostgreSQL row changed after it was read."""


class PostgresAssetFindingRepository(AssetFindingRepositoryPort):
    """PostgreSQL-backed asset/finding repository.

    Existing rows use optimistic concurrency via ``updated_at``. Objects that
    were merely read are not written back, and a modified stale object fails
    closed instead of overwriting a newer update from another process.
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
        self._asset_snapshots={}
        self._finding_snapshots={}
        self._ensure_schema()

    @staticmethod
    def _default_connect(dsn: str):
        return pooled_connection(dsn)

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

    @staticmethod
    def _version(row):
        return row[1] if not isinstance(row,dict) else row["updated_at"]

    @staticmethod
    def _serialized(item) -> str:
        return json.dumps(
            item.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",",":"),
        )

    def _track_asset(self, row) -> Asset:
        item=Asset.model_validate(self._payload(row))
        key=(item.tenant_id,item.id)
        self._tracked_assets[key]=item
        self._asset_snapshots[key]=(self._version(row),self._serialized(item))
        return item

    def _track_finding(self, row) -> Finding:
        item=Finding.model_validate(self._payload(row))
        key=(item.tenant_id,item.id)
        self._tracked_findings[key]=item
        self._finding_snapshots[key]=(self._version(row),self._serialized(item))
        return item

    def all_assets(self):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload_json,updated_at FROM assets ORDER BY tenant_id,id")
                items=[self._track_asset(row) for row in cur.fetchall()]
        return items+[
            item for item in self._pending_assets
            if (item.tenant_id,item.id) not in self._tracked_assets
        ]

    def all_findings(self):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload_json,updated_at FROM findings ORDER BY tenant_id,id")
                items=[self._track_finding(row) for row in cur.fetchall()]
        return items+[
            item for item in self._pending_findings
            if (item.tenant_id,item.id) not in self._tracked_findings
        ]

    def list_assets(self, tenant_id: str):
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json,updated_at FROM assets WHERE tenant_id=%s ORDER BY id",
                    (tenant_id,),
                )
                items=[self._track_asset(row) for row in cur.fetchall()]
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
                        "SELECT payload_json,updated_at FROM findings WHERE tenant_id=%s ORDER BY id",
                        (tenant_id,),
                    )
                else:
                    if not allowed:
                        return []
                    cur.execute(
                        "SELECT payload_json,updated_at FROM findings "
                        "WHERE tenant_id=%s AND asset_id = ANY(%s) ORDER BY id",
                        (tenant_id,list(allowed)),
                    )
                items=[self._track_finding(row) for row in cur.fetchall()]
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
                    "SELECT payload_json,updated_at FROM findings WHERE tenant_id=%s AND id=%s",
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
        return self._track_finding(row)

    def add_asset(self, asset: Asset) -> Asset:
        self._pending_assets.append(asset)
        return asset

    def add_finding(self, finding: Finding) -> Finding:
        self._pending_findings.append(finding)
        return finding

    def _persist_tracked_assets(self, cur, pending_keys: set[tuple[str,str]]) -> None:
        for key,asset in self._tracked_assets.items():
            if key in pending_keys:
                continue
            snapshot=self._asset_snapshots.get(key)
            if snapshot is None:
                continue
            version,original_payload=snapshot
            current_payload=self._serialized(asset)
            if current_payload==original_payload:
                continue
            cur.execute(
                """UPDATE assets SET payload_json=%s::jsonb,updated_at=NOW()
                   WHERE tenant_id=%s AND id=%s AND updated_at=%s""",
                (current_payload,asset.tenant_id,asset.id,version),
            )
            if int(cur.rowcount)!=1:
                raise ConcurrentUpdateError(
                    f"asset changed concurrently: {asset.tenant_id}/{asset.id}"
                )

    def _persist_tracked_findings(self, cur, pending_keys: set[tuple[str,str]]) -> None:
        for key,finding in self._tracked_findings.items():
            if key in pending_keys:
                continue
            snapshot=self._finding_snapshots.get(key)
            if snapshot is None:
                continue
            version,original_payload=snapshot
            current_payload=self._serialized(finding)
            if current_payload==original_payload:
                continue
            cur.execute(
                """UPDATE findings SET asset_id=%s,payload_json=%s::jsonb,updated_at=NOW()
                   WHERE tenant_id=%s AND id=%s AND updated_at=%s""",
                (
                    finding.asset_id,
                    current_payload,
                    finding.tenant_id,
                    finding.id,
                    version,
                ),
            )
            if int(cur.rowcount)!=1:
                raise ConcurrentUpdateError(
                    f"finding changed concurrently: {finding.tenant_id}/{finding.id}"
                )

    def persist(self) -> None:
        pending_assets={(item.tenant_id,item.id):item for item in self._pending_assets}
        pending_findings={(item.tenant_id,item.id):item for item in self._pending_findings}
        has_tracked_changes=any(
            self._serialized(item)!=self._asset_snapshots.get(key,(None,self._serialized(item)))[1]
            for key,item in self._tracked_assets.items()
        ) or any(
            self._serialized(item)!=self._finding_snapshots.get(key,(None,self._serialized(item)))[1]
            for key,item in self._tracked_findings.items()
        )
        if not pending_assets and not pending_findings and not has_tracked_changes:
            self._tracked_assets.clear()
            self._tracked_findings.clear()
            self._asset_snapshots.clear()
            self._finding_snapshots.clear()
            return

        with self._connection() as conn:
            with conn.cursor() as cur:
                self._persist_tracked_assets(cur,set(pending_assets))
                self._persist_tracked_findings(cur,set(pending_findings))
                for asset in pending_assets.values():
                    cur.execute(
                        """INSERT INTO assets(tenant_id,id,payload_json,updated_at)
                           VALUES(%s,%s,%s::jsonb,NOW())
                           ON CONFLICT(tenant_id,id) DO UPDATE SET
                             payload_json=EXCLUDED.payload_json,
                             updated_at=NOW()""",
                        (
                            asset.tenant_id,
                            asset.id,
                            self._serialized(asset),
                        ),
                    )
                for finding in pending_findings.values():
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
                            self._serialized(finding),
                        ),
                    )
        self._pending_assets.clear()
        self._pending_findings.clear()
        self._tracked_assets.clear()
        self._tracked_findings.clear()
        self._asset_snapshots.clear()
        self._finding_snapshots.clear()

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
        self._asset_snapshots={key:item for key,item in self._asset_snapshots.items() if key[0]!=tenant_id}
        self._finding_snapshots={key:item for key,item in self._finding_snapshots.items() if key[0]!=tenant_id}
        return {"assets":assets,"findings":findings}
