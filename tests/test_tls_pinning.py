def test_tls_collector_connects_to_approved_ip(monkeypatch):
    from app.collectors.tls import TLSCollector
    calls=[]
    class FakeSocket:
        def __enter__(self): return self
        def __exit__(self,*args): pass
    class FakeTLS:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def getpeercert(self, binary_form=False):
            return b"cert" if binary_form else {}
        def cipher(self): return ("TLS_AES_128_GCM_SHA256","TLSv1.3",128)
        def version(self): return "TLSv1.3"
    class FakeContext:
        def wrap_socket(self,sock,server_hostname): 
            assert server_hostname=="example.org"
            return FakeTLS()
    monkeypatch.setattr("app.collectors.tls.ssl.create_default_context",lambda:FakeContext())
    monkeypatch.setattr("app.collectors.tls._public_ip",lambda ip:True)
    monkeypatch.setattr("app.collectors.tls.socket.create_connection",lambda addr,timeout: calls.append(addr) or FakeSocket())
    TLSCollector().collect("example.org",approved_ips=["203.0.113.10"])
    assert calls == [("203.0.113.10",443)]
