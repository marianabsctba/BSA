def test_snapshot_detects_added_and_removed_assets():
    from app.change_intelligence import compare_snapshots
    from app.deep_discovery import DiscoveryPivot
    before=[DiscoveryPivot("hostname","old.example.org","dns",90,"old")]
    after=[DiscoveryPivot("hostname","new.example.org","dns",92,"new")]
    events=compare_snapshots(before,after)
    assert {(e.change_type,e.asset_key) for e in events}=={("added","new.example.org"),("removed","old.example.org")}
    assert all(e.evidence_refs for e in events)
