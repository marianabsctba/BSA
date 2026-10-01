from app.collectors.http import COMMON_SURFACE_PATHS, discover_web_surface

def test_surface_wordlist_contains_files_and_directories():
    assert "/.env" in COMMON_SURFACE_PATHS
    assert "/admin" in COMMON_SURFACE_PATHS
    assert "/swagger.json" in COMMON_SURFACE_PATHS
    assert "/backup.zip" in COMMON_SURFACE_PATHS

def test_surface_discovery_is_bounded(monkeypatch):
    calls=[]
    def fake_fetch(url,path,timeout=2.5):
        calls.append(path)
        return (404,{},b"",url+path)
    monkeypatch.setattr("app.collectors.http._safe_surface_fetch",fake_fetch)
    ev=discover_web_surface("https://example.org",max_paths=5,max_js=2)
    assert len(calls)<=6
    assert isinstance(ev,list)
