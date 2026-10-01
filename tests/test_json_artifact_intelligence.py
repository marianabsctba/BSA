from app.collectors.http import _structured_artifact_evidence

def test_json_artifact_sections_are_extracted_without_execution():
    body=b'{"openapi":"3.0.0","info":{"title":"API"},"servers":[{"url":"https://api.example.org"}],"paths":{"/users":{},"/admin":{}},"security":[{"bearerAuth":[]}]}'
    ev=_structured_artifact_evidence("https://example.org/openapi.json","json",body)
    kinds={x.kind for x in ev}
    assert "json_field:openapi" in kinds
    assert "json_section:servers" in kinds
    assert "json_section:paths" in kinds
    assert "json_section:security" in kinds

def test_malformed_json_is_ignored_safely():
    assert _structured_artifact_evidence("https://example.org/x.json","json",b'{"broken":') == []
