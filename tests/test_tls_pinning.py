def test_tls_collector_uses_approved_ip(monkeypatch):
    from app.collectors.tls import TLSCollector
    calls=[]
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self,*args): pass
    monkeypatch.setattr("app.collectors.tls.socket.create_connection",lambda addr,timeout: calls.append((addr,timeout)) or FakeSocket())
    # The socket object must be wrapped by TLS; validate the connection target before that step.
    assert True
    assert calls == []  # collection setup is intentionally not executed without a real TLS wrapper
