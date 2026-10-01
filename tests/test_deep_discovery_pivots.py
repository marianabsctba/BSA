def test_network_pivots_preserve_evidence():
    from app.deep_discovery import DiscoveryPivot, derive_network_pivots
    pivots=[DiscoveryPivot("ip","203.0.113.10","rdns",90,"ev-ip"),DiscoveryPivot("asn","AS64500","rdap",80,"ev-asn")]
    out=derive_network_pivots(pivots)
    assert any(p.kind=="reverse_dns" and p.value=="203.0.113.10" for p in out)
    assert any(p.kind=="asn" and p.value=="AS64500" for p in out)
    assert all(p.evidence_ref for p in out)

def test_certificate_pivots_only_from_certificate_evidence():
    from app.deep_discovery import DiscoveryPivot, derive_certificate_pivots
    pivots=[DiscoveryPivot("certificate","cert-1","tls",95,"ev-cert"),DiscoveryPivot("ip","203.0.113.10","tls",95,"ev-ip")]
    out=derive_certificate_pivots(pivots,["api.example.org","cdn.example.org"])
    assert {p.value for p in out}=={"api.example.org","cdn.example.org"}
    assert all(p.source=="tls" for p in out)
