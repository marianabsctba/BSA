from app.collectors.http import extract_source_map_metadata

def test_source_map_metadata_extracts_sources_and_embedded_refs():
    body=b'''{"version":3,"sourceRoot":"/src/","sources":["app.ts"],"sourcesContent":["fetch('/api/users')"]}'''
    ev=extract_source_map_metadata(body,"https://example.org/app.js.map")
    assert any(x.kind=="source_map_source" and x.value.endswith("/src/app.ts") for x in ev)
    assert any(x.kind=="source_map_embedded_reference" and "/api/users" in x.value for x in ev)
