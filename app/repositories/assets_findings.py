from __future__ import annotations

import os
from collections.abc import Iterable

from ..application.ports.asset_finding_repository import AssetFindingRepositoryPort
from ..store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS, persist_state


class AssetFindingRepository:
    """Repository boundary for asset/finding reads.

    The current adapter wraps the existing in-process store. Callers depend on
    this interface so the backing implementation can move to PostgreSQL
    without leaking storage details into API routers.
    """

    def __init__(self, assets=None, findings=None):
        self._assets = STORE_ASSETS if assets is None else assets
        self._findings = STORE_FINDINGS if findings is None else findings

    def all_assets(self):
        return self._assets

    def all_findings(self):
        return self._findings

    def list_assets(self, tenant_id: str):
        return [
            asset
            for asset in self._assets
            if getattr(asset, "tenant_id", "tenant-demo") == tenant_id
        ]

    def list_findings(
        self,
        tenant_id: str,
        asset_ids: Iterable[str] | None = None,
    ):
        allowed = set(asset_ids) if asset_ids is not None else None
        return [
            finding
            for finding in self._findings
            if getattr(finding, "tenant_id", "tenant-demo") == tenant_id
            and (allowed is None or finding.asset_id in allowed)
        ]

    def find_asset_by_value(self, tenant_id: str, value: str):
        wanted=str(value or "").strip().lower()
        return next(
            (
                asset
                for asset in self.list_assets(tenant_id)
                if str(getattr(asset, "value", "")).strip().lower()==wanted
            ),
            None,
        )

    def find_finding(self, tenant_id: str, finding_id: str):
        return next(
            (
                finding
                for finding in self.list_findings(tenant_id)
                if finding.id==finding_id
            ),
            None,
        )

    def add_asset(self, asset):
        self._assets.append(asset)
        return asset

    def add_finding(self, finding):
        self._findings.append(finding)
        return finding

    def persist(self) -> None:
        persist_state(self._assets,self._findings)

    def tenant_record_counts(self, tenant_id: str) -> dict[str,int]:
        return {
            "assets":sum(1 for item in self._assets if getattr(item,"tenant_id",None)==tenant_id),
            "findings":sum(1 for item in self._findings if getattr(item,"tenant_id",None)==tenant_id),
        }

    def purge_tenant(self, tenant_id: str) -> dict[str,int]:
        counts=self.tenant_record_counts(tenant_id)
        self._assets[:]=[
            item for item in self._assets if getattr(item,"tenant_id",None)!=tenant_id
        ]
        self._findings[:]=[
            item for item in self._findings if getattr(item,"tenant_id",None)!=tenant_id
        ]
        persist_state(self._assets,self._findings)
        return counts


def asset_finding_repository(assets=None, findings=None) -> AssetFindingRepositoryPort:
    if assets is not None or findings is not None:
        return AssetFindingRepository(assets=assets, findings=findings)

    backend=os.getenv("BSA_ASSET_REPOSITORY_BACKEND","legacy").strip().lower()
    if backend in {"legacy","sqlite","memory"}:
        return AssetFindingRepository()
    if backend=="postgres":
        dsn=os.getenv("BSA_DATABASE_URL","").strip()
        if not dsn:
            raise RuntimeError(
                "BSA_DATABASE_URL is required when "
                "BSA_ASSET_REPOSITORY_BACKEND=postgres"
            )
        from .runtime_postgres_assets_findings import RuntimePostgresAssetFindingRepository
        return RuntimePostgresAssetFindingRepository(dsn)
    raise RuntimeError(f"unsupported asset repository backend: {backend}")
