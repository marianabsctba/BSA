def test_discovery_chain_is_bounded_and_deterministic():
    from app.deep_discovery import DiscoveryPivot, expand_discovery_chain
    seed=[DiscoveryPivot("ip","203.0.113.10","rdns",90,"ev-ip")]
    out=expand_discovery_chain(seed,3)
    assert len(out)>=2
    assert out[0]==seed[0]
    assert all(p.evidence_ref for p in out)
    assert len({(p.kind,p.value,p.evidence_ref) for p in out})==len(out)
