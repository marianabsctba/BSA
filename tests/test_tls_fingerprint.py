from app.collectors.tls import TLSCollector

def test_tls_collector_source_contains_certificate_fingerprint_and_san_evidence():
    import inspect
    source=inspect.getsource(TLSCollector.collect)
    assert "certificate_sha256" in source
    assert "certificate_san" in source
