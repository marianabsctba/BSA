def test_discovery_provenance_and_candidate_ranking():
    from app.deep_discovery import DiscoveryPivot, rank_candidates
    pivots=[
        DiscoveryPivot("hostname","api.example.org","dns",94,"dns:1",("root",),"observed"),
        DiscoveryPivot("hostname","api.example.org","certificate-transparency",88,"ct:1",("root",),"observed"),
    ]
    ranked=rank_candidates(pivots)
    assert len(ranked)==1
    assert ranked[0].source_count==2
    assert "independent source corroboration" in ranked[0].rationale
    assert ranked[0].score>rank_candidates([pivots[0]])[0].score

def test_discovery_chain_has_budget_and_provenance():
    from app.deep_discovery import DiscoveryPivot, expand_discovery_chain
    seed=[DiscoveryPivot("ip","203.0.113.10","dns",95,"dns:1",(),"observed")]
    out=expand_discovery_chain(seed,max_rounds=5,max_candidates=2)
    assert len(out)<=2
    assert all(p.evidence_ref for p in out)
    assert any(p.derivation.startswith("derived:") for p in out)

def test_asn_and_hostname_validation_is_strict():
    from app.deep_discovery import build_discovery_pivots
    out=build_discovery_pivots([
        ("asn","AS64500","rdap",90,"e1"),
        ("asn","64500","bad",90,"e2"),
        ("hostname","api.example.org","dns",90,"e3"),
        ("hostname","bad host","bad",90,"e4"),
    ])
    assert [(p.kind,p.value) for p in out]==[("asn","AS64500"),("hostname","api.example.org")]
