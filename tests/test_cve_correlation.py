def test_version_range_handles_prerelease_and_numeric_segments():
    from app.cve_correlation import version_in_range
    assert version_in_range("19.2.3","19.0.0","19.2.9")
    assert not version_in_range("19.2.10","19.2.0","19.2.9")
    assert version_in_range("1.2.3-beta","1.2.0","1.2.9")

def test_cve_match_is_conservative_without_version():
    from app.cve_correlation import CVERange, match_cve
    out=match_cve("react",None,None,[CVERange("CVE-2026-1234","facebook","react","18.0.0","18.9.9")])
    assert out[0].state=="potential"
    assert out[0].confidence < 90

def test_cve_match_confirms_observed_affected_version():
    from app.cve_correlation import CVERange, match_cve
    out=match_cve("react","19.2.3","cpe:2.3:a:facebook:react:19.2.3:*:*:*:*:*:*:*",[CVERange("CVE-2026-1234","facebook","react","19.0.0","19.3.0")])
    assert out[0].state=="confirmed_affected"
    assert out[0].confidence==95
