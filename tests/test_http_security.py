from app.collectors.http import security_header_evidence


class Headers:
    def __init__(self, values):
        self.values = values

    def get(self, key):
        return self.values.get(key)


def test_security_headers_are_explicitly_measured():
    evidence = security_header_evidence(
        "https://example.org",
        Headers({"strict-transport-security": "max-age=31536000"}),
    )
    values = {item.kind: item.value for item in evidence}
    assert values["security_header:strict-transport-security"] == "max-age=31536000"
    assert values["security_header:content-security-policy"] == "missing"
    assert len(evidence) == 5
