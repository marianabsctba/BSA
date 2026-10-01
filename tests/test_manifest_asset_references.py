from app.collectors.http import extract_manifest_asset_references

def test_manifest_asset_references_parse_nested_json():
    body=b'{"pages":["/_next/static/chunks/a.js"],"nested":{"map":"/_next/static/chunks/a.js.map"}}'
    ev=extract_manifest_asset_references(body,"https://example.org/build-manifest.json")
    values={x.value for x in ev}
    assert "/_next/static/chunks/a.js" in values
    assert "/_next/static/chunks/a.js.map" in values
    assert len(ev)<=500
