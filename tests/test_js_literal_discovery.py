from app.collectors.http import extract_js_literals

def test_js_literal_discovery_extracts_routes_files_and_external_urls():
    js='''fetch("/api/users"); const a="/config.json"; const b="https://cdn.example.net/app.js"; const c="/oauth/callback"'''
    ev=extract_js_literals(js,"https://example.org/app.js")
    kinds={x.kind for x in ev}
    assert "js_route_literal" in kinds
    assert "js_file_reference" in kinds
    assert "js_external_url_literal" in kinds
    assert len(ev)<=500
