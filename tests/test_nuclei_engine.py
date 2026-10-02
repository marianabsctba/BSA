import json
import subprocess

import pytest

from app.nuclei_engine import run_nuclei, NucleiEngineError


def test_nuclei_adapter_normalizes_jsonl(monkeypatch):
    class Completed:
        returncode = 0
        stdout = json.dumps({"template-id":"xss-test","info":{"name":"XSS","severity":"medium","classification":{"cve-id":"CVE-2026-0001"}},"matched-at":"https://1.1.1.1/"})
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Completed())
    monkeypatch.setattr("app.nuclei_engine.shutil.which", lambda name: "/usr/bin/nuclei")
    result = run_nuclei("https://1.1.1.1/", profile="safe")
    assert result["engine"] == "nuclei"
    assert result["findings"][0]["template_id"] == "xss-test"
    assert result["findings"][0]["cve_id"] == "CVE-2026-0001"


def test_nuclei_adapter_never_uses_shell(monkeypatch):
    captured = {}
    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""
    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return Completed()
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("app.nuclei_engine.shutil.which", lambda name: "/usr/bin/nuclei")
    run_nuclei("https://1.1.1.1/", profile="safe")
    assert captured["shell"] is False
    assert captured["check"] is False


def test_nuclei_adapter_rejects_unsupported_profile(monkeypatch):
    monkeypatch.setattr("app.nuclei_engine.shutil.which", lambda name: "/usr/bin/nuclei")
    with pytest.raises(ValueError):
        run_nuclei("https://1.1.1.1/", profile="aggressive")


def test_nuclei_adapter_reports_missing_engine(monkeypatch):
    monkeypatch.setattr("app.nuclei_engine.shutil.which", lambda name: None)
    with pytest.raises(NucleiEngineError):
        run_nuclei("https://1.1.1.1/")


def test_nuclei_rejects_hostname_in_production(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    with pytest.raises(ValueError,match="hostname targets are disabled"):
        run_nuclei("https://example.com/", profile="safe")


def test_nuclei_accepts_explicit_public_ip_in_production(monkeypatch):
    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Completed())
    monkeypatch.setattr("app.nuclei_engine.shutil.which", lambda name: "/usr/bin/nuclei")
    result = run_nuclei("https://1.1.1.1/", profile="safe")
    assert result["target"] == "https://1.1.1.1/"
