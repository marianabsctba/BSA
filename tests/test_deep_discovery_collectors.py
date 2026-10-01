def test_pivots_from_dns_and_ct_evidence():
    from app.deep_discovery import pivots_from_evidence
    from app.collectors.base import Evidence
    ev=[
        Evidence("dns","example.org","a_record","203.0.113.10",95,{}),
        Evidence("dns","example.org","alias","api.example.org",90,{}),
        Evidence("certificate-transparency","example.org","certificate_name","admin.example.org",88,{"passive":True}),
    ]
    out=pivots_from_evidence(ev)
    assert ("ip","203.0.113.10") in {(p.kind,p.value) for p in out}
    assert ("hostname","api.example.org") in {(p.kind,p.value) for p in out}
    assert ("hostname","admin.example.org") in {(p.kind,p.value) for p in out}
    assert all(p.evidence_ref for p in out)

def test_collect_discovery_pivots_uses_only_supplied_collectors():
    from app.deep_discovery import collect_discovery_pivots
    from app.collectors.base import Evidence
    class C:
        def collect(self,target):
            return [Evidence("test",target,"a_record","203.0.113.20",91,{})]
    out=collect_discovery_pivots("example.org",[C()])
    assert out[0].value=="203.0.113.20"
