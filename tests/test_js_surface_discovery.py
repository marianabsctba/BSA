from app.collectors.http import discover_web_surface

def test_web_surface_extracts_same_origin_js_endpoints(monkeypatch):
    def fake_fetch(url,path,timeout=2.5):
        if path=="/":
            return (200,{"content-type":"text/html"},b'<html><script src="/app.js"></script></html>',url)
        if path=="/app.js":
            return (200,{"content-type":"application/javascript"},b'fetch("/api/users"); "/config.json"',url)
        return (404,{},b"",url+path)
    monkeypatch.setattr("app.collectors.http._safe_surface_fetch",fake_fetch)
    ev=discover_web_surface("https://example.org",max_paths=2,max_js=2)
    kinds=[e.kind for e in ev]
    assert "javascript_asset" in kinds
    assert "js_endpoint_reference" in kinds
    assert "js_artifact_reference" in kinds
