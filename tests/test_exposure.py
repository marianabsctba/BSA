from app.exposure import exposure_band, exposure_breakdown
from app.models import Asset, AssetType, Finding, Severity


def asset():
    return Asset(
        id="a1",
        value="vpn.example.org",
        type=AssetType.SUBDOMAIN,
        confidence=95,
        criticality=5,
        source="dns",
        tags=["internet-facing", "remote-access", "production"],
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-01T00:00:00+00:00",
    )


def test_exposure_is_explainable_and_bounded():
    finding = Finding(
        id="f1",
        asset_id="a1",
        title="admin exposed",
        severity=Severity.HIGH,
        confidence=90,
        evidence="controlled discovery",
    )
    result = exposure_breakdown(asset(), [finding])
    assert 0 <= result.score <= 100
    assert result.internet > 0
    assert result.criticality == 20
    assert result.rationale


def test_exposure_band():
    assert exposure_band(90) == "critical"
    assert exposure_band(75) == "high"
    assert exposure_band(50) == "medium"
    assert exposure_band(20) == "low"
