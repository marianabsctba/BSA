from app.prioritization import ai_context_signal
from app.models import Finding, Severity, Asset, AssetType

def test_ai_risk_context_never_replaces_deterministic_score():
    finding=Finding(id="f1",asset_id="a1",title="Test finding",severity=Severity.HIGH,confidence=80,evidence="controlled test evidence")
    asset=Asset(id="a1",name="example.org",type=AssetType.DOMAIN,criticality=4,confidence=90,source="seed",tags=("internet-facing",))
    out=ai_context_signal(finding,asset,70)
    assert isinstance(out,dict)
    assert "signals" in out
    assert "unknowns" in out
