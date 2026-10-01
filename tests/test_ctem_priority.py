def test_ctem_priority_uses_exposure_and_business_context():
    from app.risk_engine import assess_ctem_priority
    from app.models import Finding, Asset, AssetType, Severity
    f=Finding(id="f",asset_id="a",title="x",severity=Severity.HIGH,confidence=90,evidence="x",cvss=9.8,epss=0.9,kev=True)
    a=Asset(id="a",value="app.example.org",type=AssetType.APPLICATION,confidence=95,criticality=5,tags=["internet-facing","production"],first_seen="2026-10-01",last_seen="2026-10-01")
    result=assess_ctem_priority(f,a)
    assert 0 <= result["priority"] <= 100
    assert result["action"] in {"immediate","expedite","plan","monitor"}
    assert result["exposure"] > 0
    assert result["business_criticality"] == 100
