def test_change_intelligence_detects_evidence_change():
    from app.change_intelligence import compare_snapshots
    from app.deep_discovery import DiscoveryPivot
    before=[DiscoveryPivot("hostname","api.example.org","dns",90,"dns-old")]
    after=[DiscoveryPivot("hostname","api.example.org","certificate-transparency",98,"ct-new")]
    events=compare_snapshots(before,after)
    assert len(events)==1
    assert events[0].change_type=="evidence_changed"
    assert events[0].before=="dns-old" and events[0].after=="ct-new"
    assert set(events[0].evidence_refs)=={"dns-old","ct-new"}

def test_change_classification_raises_internet_exposed_addition():
    from app.change_intelligence import ChangeEvent, classify_change
    e=ChangeEvent("api.example.org","added",None,"api.example.org",("e1",),95)
    out=classify_change(e,{"internet_exposed":True})
    assert out.severity=="warning"
