from app.collectors.http import analyze_public_artifact_references

def test_json_artifact_analysis_extracts_openapi_and_refs():
    body=b'{"openapi":"3.0.0","paths":{"/admin":{"get":{}}},"config":"/config.json"}'
    ev=analyze_public_artifact_references("https://example.org/openapi.json",body,"application/json")
    assert any(x.kind=="openapi_endpoint" for x in ev)
    assert any(x.kind=="discovery_candidate" for x in ev)

def test_sourcemap_analysis_records_sources_without_fetching():
    body=b'{"version":3,"sources":["webpack:///src/app.ts","webpack:///src/auth.ts"]}'
    ev=analyze_public_artifact_references("https://example.org/app.js.map",body,"application/json")
    assert {x.value for x in ev if x.kind=="sourcemap_source"} == {"webpack:///src/app.ts","webpack:///src/auth.ts"}
