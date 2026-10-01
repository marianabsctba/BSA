from app.collectors.http import extract_source_map_metadata

def test_source_map_metadata_records_exposure_without_executing_source():
    body=b'{"version":3,"sources":["webpack:///src/app.ts"],"names":["login"],"sourcesContent":["const x=1"]}'
    ev=extract_source_map_metadata(body,"https://example.org/app.js.map")
    meta=next(x for x in ev if x.kind=="sourcemap_metadata")
    assert meta.metadata["source_count"]==1
    assert meta.metadata["name_count"]==1
    assert meta.metadata["has_sources_content"] is True
    assert any(x.kind=="sourcemap_source" for x in ev)
