from app.models import Asset, AssetType, Finding, Severity
from app.prioritization import prioritize_finding


def test_contextual_priority_is_not_cvss_only():
    asset = Asset(
        id="a1",
        value="vpn.example.org",
        type=AssetType.APPLICATION,
        confidence=95,
        criticality=5,
        source="authoritative",
        tags=["internet-facing", "remote-access", "production"],
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-01T00:00:00Z",
    )
    finding = Finding(
        id="f1",
        asset_id="a1",
        title="critical finding",
        severity=Severity.CRITICAL,
        confidence=95,
        evidence="verified",
    )
    result = prioritize_finding(finding, asset, path_score=90)
    assert result.priority == "P1"
    assert result.score >= 85
    assert result.impact >= 70
    assert "ativo de alta criticidade" in result.reasons
    assert "presente em caminho de exposição prioritário" in result.reasons
