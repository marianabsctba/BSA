from datetime import datetime, timezone

from app.models import Asset, AssetType, Finding, Severity
from app import store


def test_asset_and_finding_state_survives_reload(tmp_path, monkeypatch):
    db = tmp_path / "store.db"
    monkeypatch.setenv("BSA_STORE_DB", str(db))
    now = datetime.now(timezone.utc).isoformat()

    asset = Asset(
        tenant_id="tenant-persist",
        id="ast-persist",
        value="api.example.org",
        type=AssetType.SUBDOMAIN,
        first_seen=now,
        last_seen=now,
        evidence_count=2,
        sources=["assessment-intelligence"],
    )
    finding = Finding(
        tenant_id="tenant-persist",
        id="fdg-persist",
        asset_id=asset.id,
        title="Persisted finding",
        severity=Severity.HIGH,
        evidence="observed evidence",
        vulnerability_id="CVE-2026-12345",
    )

    store.persist_state([asset], [finding])
    assets, findings = store._load_persisted()

    loaded_asset = next(x for x in assets if x.id == asset.id)
    loaded_finding = next(x for x in findings if x.id == finding.id)
    assert loaded_asset.tenant_id == "tenant-persist"
    assert loaded_asset.value == "api.example.org"
    assert loaded_asset.evidence_count == 2
    assert loaded_finding.tenant_id == "tenant-persist"
    assert loaded_finding.asset_id == asset.id
    assert loaded_finding.vulnerability_id == "CVE-2026-12345"
