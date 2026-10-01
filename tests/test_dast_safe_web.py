import app.dast as dast


def _fake_fetch_factory(body=b"<html><script src='/app.js'></script><form action='/login'></form></html>", status=200, headers=None):
    calls=[]
    headers=headers or {"content-type":"text/html"}
    def fake(url, **kwargs):
        calls.append((url, kwargs))
        return status, headers, body, url
    return fake, calls


def test_safe_dast_emits_header_and_surface_findings(monkeypatch):
    fake, calls = _fake_fetch_factory()
    monkeypatch.setattr(dast, "validate_external_target", lambda target: None)
    monkeypatch.setattr(dast, "resolve_public", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dast, "_pinned_fetch", fake)
    result = dast.run_safe_web_assessment("https://example.test/")
    checks = {f["check"] for f in result["findings"]}
    assert "security_headers" in checks
    assert any(f["check"] == "surface_inventory" and "forms observed" in f["title"] for f in result["findings"])
    assert any(f["check"] == "surface_inventory" and "scripts observed" in f["title"] for f in result["findings"])
    assert all("example.test" in call[0] for call in calls)


def test_safe_dast_inventory_and_validates_only_documented_get(monkeypatch):
    spec = b'{"openapi":"3.0.0","paths":{"/health":{"get":{"operationId":"health"}},"/users/{id}":{"get":{"operationId":"user"}},"/write":{"post":{"operationId":"write"}}}}'
    fake, calls = _fake_fetch_factory(body=spec, headers={"content-type":"application/json"})
    monkeypatch.setattr(dast, "validate_external_target", lambda target: None)
    monkeypatch.setattr(dast, "resolve_public", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dast, "_pinned_fetch", fake)
    result = dast.run_safe_web_assessment("https://example.test/openapi.json")
    assert {x["method"] for x in result["api_inventory"]} == {"GET", "POST"}
    assert any(x["path"] == "/users/{id}" and x["status"] == "template" for x in result["api_validation"])
    assert any(x["path"] == "/health" and x["method"] == "GET" for x in result["api_validation"])
    assert not any(x["path"] == "/write" for x in result["api_validation"])


def test_safe_dast_records_get_5xx_as_finding(monkeypatch):
    fake, _ = _fake_fetch_factory(body=b"{}", status=503, headers={"content-type":"text/html"})
    monkeypatch.setattr(dast, "validate_external_target", lambda target: None)
    monkeypatch.setattr(dast, "resolve_public", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dast, "_pinned_fetch", fake)
    result = dast.run_safe_web_assessment("https://example.test/")
    assert any(f["check"] == "http_status" and f["severity"] == "medium" for f in result["findings"])


def test_safe_dast_does_not_follow_external_links(monkeypatch):
    body=b'<a href="https://outside.example/secret">external</a><a href="/inside">inside</a>'
    fake, calls = _fake_fetch_factory(body=body)
    monkeypatch.setattr(dast, "validate_external_target", lambda target: None)
    monkeypatch.setattr(dast, "resolve_public", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dast, "_pinned_fetch", fake)
    dast.run_safe_web_assessment("https://example.test/")
    assert not any("outside.example" in call[0] for call in calls)


def test_safe_dast_exposes_api_validation_as_evidence(monkeypatch):
    spec = b'{"openapi":"3.0.0","paths":{"/health":{"get":{"operationId":"health"}},"/users/{id}":{"get":{"operationId":"user"}}}}'
    def fake(url, **kwargs):
        return 200, {"content-type":"application/json"}, spec, url
    monkeypatch.setattr(dast, "validate_external_target", lambda target: None)
    monkeypatch.setattr(dast, "resolve_public", lambda host: ["203.0.113.10"])
    monkeypatch.setattr(dast, "_pinned_fetch", fake)
    result = dast.run_safe_web_assessment("https://example.test/openapi.json")
    assert any(x["check"] == "api_status" for x in result["evidence"])
    assert any(x["check"] == "api_template" for x in result["evidence"])
