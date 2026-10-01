from app.asset_identity import normalize_asset_value, provenance_confidence
from app.correlation import correlate_evidence


def test_normalizes_wildcard_and_trailing_dot_to_one_identity():
    assets = correlate_evidence(
        "example.org",
        [
            {
                "source": "certificate-transparency",
                "kind": "certificate_name",
                "value": "*.API.Example.ORG.",
                "confidence": 90,
            },
            {
                "source": "http",
                "kind": "http_status",
                "subject": "https://api.example.org",
                "value": "200",
                "confidence": 98,
            },
        ],
    )

    api = [a for a in assets if a.value == "api.example.org"]
    assert len(api) == 1
    assert api[0].asset_type == "application"
    assert api[0].evidence_count == 2
    assert len(api[0].evidence_refs) == 2


def test_normalizes_url_and_ipv6_identity_values():
    assert normalize_asset_value("application", "HTTPS://API.Example.org/path") == "api.example.org"
    assert normalize_asset_value("ip", "2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"


def test_explicit_evidence_reference_is_preserved():
    assets = correlate_evidence(
        "example.org",
        [
            {
                "source": "ct",
                "kind": "certificate_name",
                "value": "api.example.org",
                "confidence": 92,
                "metadata": {"evidence_ref": "ct:cert:abc123"},
            }
        ],
    )
    api = [a for a in assets if a.value == "api.example.org"][0]
    assert api.evidence_refs == ("ct:cert:abc123",)


def test_provenance_confidence_rewards_independent_sources_but_is_bounded():
    assert provenance_confidence([80, 90], 2, 2) == 88
    assert provenance_confidence([100, 100, 100], 5, 10) == 100
