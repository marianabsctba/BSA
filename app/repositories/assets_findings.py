from __future__ import annotations

from collections.abc import Iterable

from ..store import ASSETS as STORE_ASSETS, FINDINGS as STORE_FINDINGS


class AssetFindingRepository:
    """Repository boundary for asset/finding reads.

    The current adapter wraps the existing in-process store. Callers depend on
    this interface so the backing implementation can move to PostgreSQL
    without leaking storage details into API routers.
    """

    def __init__(self, assets=None, findings=None):
        self._assets = STORE_ASSETS if assets is None else assets
        self._findings = STORE_FINDINGS if findings is None else findings

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


def asset_finding_repository(assets=None, findings=None) -> AssetFindingRepository:
    return AssetFindingRepository(assets=assets, findings=findings)
