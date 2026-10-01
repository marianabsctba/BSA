import app.collectors.http as http


def test_pinned_fetch_connects_to_validated_ip(monkeypatch):
    calls=[]
    class FakeSock:
        def close(self): pass
    class FakeResponse:
        status=200
        def read(self,n): return b"ok"
        def getheaders(self): return [("content-type","text/plain")]
    class FakeConn:
        def __init__(self,host,approved_ip,port=None,timeout=4.0):
            calls.append((host,approved_ip,port))
        def request(self,*a,**k): pass
        def getresponse(self): return FakeResponse()
        def close(self): pass
    monkeypatch.setattr(http,"_PinnedHTTPConnection",FakeConn)
    monkeypatch.setattr(http,"_PinnedHTTPSConnection",FakeConn)
    monkeypatch.setattr("app.security.resolve_public",lambda host:["203.0.113.10"])
    status,headers,body,url=http._pinned_fetch("http://example.org/admin")
    assert status==200 and body==b"ok"
    assert calls == [("example.org","203.0.113.10",80)]
