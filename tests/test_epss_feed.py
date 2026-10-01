def test_epss_ingestion(monkeypatch):
    from app import vulnerability_feeds as vf
    monkeypatch.setattr(vf,"_get_json",lambda url,timeout:{"data":[{"cve":"CVE-2026-1","epss":"0.73"},{"cve":"CVE-2026-2","epss":"1.2"},{"cve":"CVE-2026-3","epss":"bad"}]})
    assert vf.ingest_epss("https://feed.invalid")=={"CVE-2026-1":0.73}
