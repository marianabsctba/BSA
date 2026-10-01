from app.collectors.http import extract_source_map_metadata

def test_source_map_reference_classification():
    body=b'''{"version":3,"sources":["app.ts"],"sourcesContent":["fetch('/api/users'); fetch('https://cdn.example.com/x.js'); fetch('/config.json')"]}'''
    ev=extract_source_map_metadata(body,"https://example.org/app.js.map")
    kinds={x.kind for x in ev}
    assert "source_map_api_reference" in kinds
    assert "source_map_external_reference" in kinds
    assert "source_map_config_reference" in kinds
