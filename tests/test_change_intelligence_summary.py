def test_change_summary_counts_types_and_warnings():
    from app.change_intelligence import ChangeEvent, summarize_changes
    events=[
        ChangeEvent("a","added",None,"a",("e1",),90,"warning"),
        ChangeEvent("b","removed","b",None,("e2",),80,"info"),
        ChangeEvent("c","evidence_changed","e1","e2",("e1","e2"),95,"warning"),
    ]
    out=summarize_changes(events)
    assert out["total"]==3
    assert out["by_type"]["added"]==1
    assert out["by_type"]["evidence_changed"]==1
    assert out["warnings"]==2

def test_change_event_keeps_structured_metadata():
    from app.change_intelligence import compare_snapshots
    from app.deep_discovery import DiscoveryPivot
    b=[DiscoveryPivot("hostname","api.example.org","dns",80,"e1")]
    a=[DiscoveryPivot("hostname","api.example.org","ct",98,"e2")]
    e=compare_snapshots(b,a)[0]
    assert e.metadata["kind"]=="hostname"
    assert e.metadata["confidence_delta"]==18
