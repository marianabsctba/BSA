from app.collectors.http import extract_js_surface_references

def test_js_surface_references_extract_chunks_maps_endpoints_and_artifacts():
    js='''"/app.abc123.chunk.js"; "/app.js.map"; "/api/users"; "/config.json"'''
    ev=extract_js_surface_references(js,"https://example.org/app.js")
    kinds={x.kind for x in ev}
    assert "js_chunk_reference" in kinds
    assert "js_sourcemap_reference" in kinds
    assert "js_endpoint_reference" in kinds
    assert "js_artifact_reference" in kinds
    assert len(ev)<=200
