from app.collectors.http import discover_web_surface

def test_source_map_candidate_is_analyzed(monkeypatch):
    def fake_fetch(url,path,timeout=2.5):
        if path=="/":
            return (200,{"content-type":"text/html"},b'<script src="/app.js"></script>',url)
        if path=="/app.js":
            return (200,{"content-type":"application/javascript"},b'//# sourceMappingURL=app.js.map',url)
        if path=="/app.js.map":
            return (200,{"content-type":"application/json"},b'{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}',url)
        return (404,{},b"",url+path)
    monkeypatch.setattr("app.collectors.http._safe_surface_fetch",fake_fetch)
    ev=discover_web_surface("https://example.org",max_paths=2,max_js=2)
    assert any(x.kind=="source_map_analyzed" for x in ev)
