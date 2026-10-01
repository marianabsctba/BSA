from app.collectors.http import artifact_discovery_candidates

def test_artifact_candidates_are_bounded_and_deduplicated():
    body=b'{"paths":["/api/users","/admin"],"external":"https://evil.example/x","same":"/api/users"}'
    ev=artifact_discovery_candidates("https://example.org/openapi.json","json",body)
    values=[e.value for e in ev]
    assert "https://example.org/api/users" in values
    assert "https://evil.example/x" in values
    assert len(values)==len(set(values))
    assert len(values)<=100
