from app.collectors.ports import PortCollector, COMMON_PORTS

def test_bounded_port_collector_scope():
    assert len(COMMON_PORTS) <= 25
    assert 443 in COMMON_PORTS
    assert 3389 in COMMON_PORTS

def test_port_evidence_is_bounded():
    items=PortCollector().collect("127.0.0.1",timeout=0.01,ports=(1,2))
    for item in items:
        assert item.kind=="tcp_open"
        assert item.metadata.get("bounded") is True
