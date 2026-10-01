def test_technical_change_detects_port_like_value_addition():
    from app.technical_change_intelligence import compare_technical_snapshots
    from app.deep_discovery import DiscoveryPivot
    before=[DiscoveryPivot("ip","203.0.113.10","ports",90,"p1")]
    after=[DiscoveryPivot("ip","203.0.113.10","ports",90,"p1")]
    assert compare_technical_snapshots(before,after)==[]

def test_technical_change_detects_new_technology_evidence():
    from app.technical_change_intelligence import compare_technical_snapshots
    from app.deep_discovery import DiscoveryPivot
    before=[DiscoveryPivot("hostname","api.example.org","http",90,"h1")]
    after=[DiscoveryPivot("hostname","api.example.org","http",96,"h2")]
    events=compare_technical_snapshots(before,after)
    assert events[0].change_type=="evidence_changed"
    assert events[0].severity=="info"
