from app.integration_export import siem_events
from app.models import Asset, AssetType, Finding, Severity


def _asset(tenant_id: str, asset_id: str, value: str):
    return Asset(
        tenant_id=tenant_id,
        id=asset_id,
        value=value,
        type=AssetType.APPLICATION,
        confidence=90,
        criticality=4,
        tags=["internet-facing"],
        first_seen="2026-10-01T00:00:00+00:00",
        last_seen="2026-10-01T00:00:00+00:00",
    )


def _finding(tenant_id: str, finding_id: str, asset_id: str, detected_at: str):
    return Finding(
        tenant_id=tenant_id,
        id=finding_id,
        asset_id=asset_id,
        title="Exposure",
        severity=Severity.HIGH,
        confidence=92,
        evidence="normalized evidence",
        vulnerability_id="CVE-2026-4242",
        cvss=8.8,
        epss=0.81,
        kev=True,
        validation_state="confirmed",
        evidence_quality=90,
        detected_at=detected_at,
        affected_components=["https://api.example.org/login"],
        independent_source_count=2,
        independently_corroborated=True,
    )


def test_siem_export_is_tenant_scoped_and_engine_private():
    assets=[
        _asset("tenant-a","asset-a","api.example.org"),
        _asset("tenant-b","asset-b","other.example.org"),
    ]
    findings=[
        _finding("tenant-a","finding-a","asset-a","2026-10-01T10:00:00+00:00"),
        _finding("tenant-b","finding-b","asset-b","2026-10-01T11:00:00+00:00"),
    ]

    payload=siem_events("tenant-a",assets,findings)

    assert payload["count"] == 1
    event=payload["events"][0]
    assert event["tenant_id"] == "tenant-a"
    assert event["asset"]["value"] == "api.example.org"
    assert event["finding"]["independently_corroborated"] is True
    assert "nuclei" not in str(payload).lower()
    assert "zap" not in str(payload).lower()


def test_siem_export_supports_incremental_cursor_and_limit():
    assets=[_asset("tenant-a","asset-a","api.example.org")]
    findings=[
        _finding("tenant-a","finding-1","asset-a","2026-10-01T10:00:00+00:00"),
        _finding("tenant-a","finding-2","asset-a","2026-10-01T11:00:00+00:00"),
        _finding("tenant-a","finding-3","asset-a","2026-10-01T12:00:00+00:00"),
    ]

    payload=siem_events(
        "tenant-a",
        assets,
        findings,
        since="2026-10-01T10:00:00+00:00",
        limit=1,
    )

    assert payload["count"] == 1
    assert payload["events"][0]["event_id"] == "finding:finding-2"
    assert payload["next_cursor"] == "2026-10-01T11:00:00+00:00"
