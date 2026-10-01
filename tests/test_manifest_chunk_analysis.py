from app.collectors.http import discover_web_surface

def test_manifest_discovered_js_is_analyzed(monkeypatch):
    def fake_fetch(url,path,timeout=2.5):
        if path=="/":
            return (200,{"content-type":"text/html"},b'<script src="/build-manifest.json"></script>',url)
        if path=="/build-manifest.json":
            return (200,{"content-type":"application/json"},b'{"chunk":"/_next/static/chunks/app.js"}',url)
        if path=="/_next/static/chunks/app.js":
            return (200,{"content-type":"application/javascript"},b'fetch("/api/from-chunk")',url)
        return (404,{},b"",url+path)
    monkeypatch.setattr("app.collectors.http._safe_surface_fetch",fake_fetch)
    ev=discover_web_surface("https://example.org",max_paths=2,max_js=2)
    assert any(x.kind=="manifest_asset_analyzed" for x in ev)
    assert any(x.value=="/api/from-chunk" for x in ev if x.kind=="js_route_literal")
