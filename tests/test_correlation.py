from app.correlation import correlate_evidence


def test_correlates_duplicate_web_and_certificate_evidence():
    assets = correlate_evidence(
        "example.org",
        [
            {"source": "certificate-transparency", "kind": "certificate_name", "value": "api.example.org", "confidence": 88},
            {"source": "http", "kind": "http_status", "subject": "https://api.example.org", "value": "200", "confidence": 98},
            {"source": "http", "kind": "security_header:content-security-policy", "subject": "https://api.example.org", "value": "missing", "confidence": 97},
        ],
    )
    api = [a for a in assets if a.value == "api.example.org"]
    assert api
    assert api[0].confidence >= 90
    assert "certificate-transparency" in api[0].sources
    assert "http" in api[0].sources
