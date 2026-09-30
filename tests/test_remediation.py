from app.models import Asset, AssetType, Finding, Severity
from app.remediation import build_remediation_plan


def test_remediation_plan_shows_residual_risk_and_validation():
    asset = Asset(
        id="a1",
        value="vpn.example.org",
        type=AssetType.APPLICATION,
        confidence=95,
        criticality=5,
        tags=["internet-facing", "remote-access", "production"],
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-01T00:00:00Z",
    )
    finding = Finding(
        id="f1",
        asset_id="a1",
        title="critical exposure",
        severity=Severity.CRITICAL,
        confidence=95,
        evidence="verified",
    )
    plan = build_remediation_plan(finding, asset)
    assert plan.priority == "P1"
    assert plan.current_score > plan.residual_score
    assert plan.risk_reduction > 0
    assert plan.validation
    assert plan.owner
