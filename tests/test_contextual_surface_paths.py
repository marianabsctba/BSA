from app.collectors.http import contextual_surface_paths

def test_contextual_paths_are_derived_and_bounded():
    ev=[
      {"kind":"js_endpoint_reference","value":"/api/users"},
      {"kind":"js_artifact_reference","value":"/config/app.json"},
      {"kind":"technology_version","value":"wordpress:6.0","metadata":{"product":"wordpress","version":"6.0"}},
    ]
    paths=contextual_surface_paths(ev,max_paths=20)
    assert "/api/users" in paths
    assert "/config/app.json" in paths
    assert "/wp-admin/" in paths
    assert len(paths)<=20
