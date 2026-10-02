from datetime import datetime, timezone

from app.models import Asset, AssetType, Finding, Severity
from app.repositories.assets_findings import AssetFindingRepository


def _asset(tenant_id: str, asset_id: str, value: str):
    now=datetime.now(timezone.utc).isoformat()
    return Asset(
        tenant_id=tenant_id,
        id=asset_id,
        value=value,
        type=AssetType.DOMAIN,
        first_seen=now,
        last_seen=now,
    )


def _finding(tenant_id: str, finding_id: str, asset_id: str):
    return Finding(
        tenant_id=tenant_id,
        id=finding_id,
        asset_id=asset_id,
        title="Repository finding",
        severity=Severity.MEDIUM,
        evidence="repository-boundary-test",
    )


def test_repository_isolates_tenants_and_supports_lookup():
    a=_asset("tenant-a","asset-a","a.example.org")
    b=_asset("tenant-b","asset-b","b.example.org")
    fa=_finding("tenant-a","finding-a","asset-a")
    fb=_finding("tenant-b","finding-b","asset-b")
    repository=AssetFindingRepository([a,b],[fa,fb])

    assert repository.list_assets("tenant-a")==[a]
    assert repository.list_findings("tenant-a",{"asset-a"})==[fa]
    assert repository.find_asset_by_value("tenant-a","A.EXAMPLE.ORG") is a
    assert repository.find_asset_by_value("tenant-a","b.example.org") is None
    assert repository.find_finding("tenant-a","finding-a") is fa
    assert repository.find_finding("tenant-a","finding-b") is None


def test_repository_write_boundary_appends_and_persists(monkeypatch):
    assets=[]
    findings=[]
    repository=AssetFindingRepository(assets,findings)
    asset=_asset("tenant-a","asset-a","a.example.org")
    finding=_finding("tenant-a","finding-a","asset-a")
    captured={}

    monkeypatch.setattr(
        "app.repositories.assets_findings.persist_state",
        lambda current_assets,current_findings: captured.update(
            assets=list(current_assets),
            findings=list(current_findings),
        ),
    )

    assert repository.add_asset(asset) is asset
    assert repository.add_finding(finding) is finding
    repository.persist()

    assert assets==[asset]
    assert findings==[finding]
    assert captured=={"assets":[asset],"findings":[finding]}
