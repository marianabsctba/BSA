from app.cve_correlation import CVERange,enrich_cve_matches

def test_cve_match_requires_cpe_consistency_when_present():
    c=CVERange("CVE-2026-0001","vendor-a","product-x","1.0","2.0")
    out=enrich_cve_matches("product-x","1.5","cpe:2.3:a:vendor-a:product-x:1.5:*:*:*:*:*:*:*",[c])
    assert out[0].state=="confirmed_affected"
    bad=enrich_cve_matches("product-x","1.5","cpe:2.3:a:other:product-y:1.5:*:*:*:*:*:*:*",[c])
    assert bad[0].state=="needs_validation"
