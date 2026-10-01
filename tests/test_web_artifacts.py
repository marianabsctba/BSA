from app.collectors.http import _artifact_evidence


def test_public_json_artifact_is_recorded_without_execution():
    body=b'{"openapi":"3.0.0","servers":[{"url":"https://api.example.com"}]}'
    evidence=_artifact_evidence(
        "https://example.com/openapi.json",
        {"content-type":"application/json"},
        body,
    )
    assert any(e.kind=="web_artifact:json" for e in evidence)
    refs=[e.value for e in evidence if e.kind=="artifact_reference"]
    assert "https://api.example.com" in refs


def test_artifact_discovery_is_bounded():
    body=b"x"*100000
    evidence=_artifact_evidence(
        "https://example.com/data.json",
        {"content-type":"application/json"},
        body,
    )
    assert all(len(e.value)<=500 for e in evidence)
