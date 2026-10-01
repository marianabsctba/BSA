from app.collectors.http import _versioned_technology_evidence

def test_versioned_fingerprint_extracts_product_and_version():
    ev=_versioned_technology_evidence("https://example.org","server_header","nginx/1.24.0")
    versions=[x for x in ev if x.kind=="technology_version"]
    assert versions
    assert versions[0].metadata["product"].lower()=="nginx"
    assert versions[0].metadata["version"]=="1.24.0"

def test_versioned_fingerprint_does_not_invent_without_version():
    ev=_versioned_technology_evidence("https://example.org","server_header","nginx")
    assert not [x for x in ev if x.kind=="technology_version"]
