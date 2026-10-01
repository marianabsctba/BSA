def test_discovery_pivots_require_evidence_and_valid_values():
    from app.deep_discovery import build_discovery_pivots
    rows=[
        ("ip","203.0.113.10","rdns",90,"ev-1"),
        ("hostname","api.example.org","ct",88,"ev-2"),
        ("ip","not-an-ip","bad",90,"ev-3"),
        ("hostname","bad host","bad",90,"ev-4"),
        ("hostname","api.example.org","ct",88,""),
    ]
    pivots=build_discovery_pivots(rows)
    assert [(p.kind,p.value) for p in pivots]==[("ip","203.0.113.10"),("hostname","api.example.org")]

def test_discovery_pivot_candidates_filter():
    from app.deep_discovery import DiscoveryPivot, pivot_candidates
    pivots=[
        DiscoveryPivot("asn","AS64500","asn",90,"e1"),
        DiscoveryPivot("ip","203.0.113.10","rdns",90,"e2"),
    ]
    out=pivot_candidates(pivots,{"ip"})
    assert len(out)==1 and out[0].kind=="ip"
