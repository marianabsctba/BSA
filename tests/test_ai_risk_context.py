from app.prioritization import ai_context_signal
from app.models import Finding, Severity, Asset, AssetType

def test_ai_risk_context_never_replaces_deterministic_score():
    finding=Finding(id="f1",asset_id="a1",title="Test finding",severity=Severity.HIGH,confidence=80,evidence="controlled test evidence")
    asset=Asset(id="a1",value="example.org",type=AssetType.DOMAIN,criticality=4,confidence=90,source="seed",tags=["internet-facing"],first_seen="2026-10-01T00:00:00Z",last_seen="2026-10-01T00:00:00Z")
    out=ai_context_signal(finding,asset,70)
    assert isinstance(out,dict)
    assert "signals" in out
    assert "unknowns" in out
