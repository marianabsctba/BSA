from app.assessment_registry import registry
from app.safe_nuclei_provider import SafeNucleiProvider


def test_registry_uses_hardened_nuclei_provider():
    provider = registry.provider("nuclei")
    assert isinstance(provider, SafeNucleiProvider)


def test_nuclei_redirects_are_disabled_for_ip_targets(monkeypatch):
    monkeypatch.setenv("BSA_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    command = SafeNucleiProvider()._command("203.0.113.10")

    assert "-dr" in command or "-disable-redirects" in command
    assert "-fr" not in command
    assert "-follow-redirects" not in command
    assert "-fhr" not in command
    assert "-follow-host-redirects" not in command


def test_nuclei_redirects_are_disabled_for_hostname_targets(monkeypatch):
    monkeypatch.setenv("BSA_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    command = SafeNucleiProvider()._command("example.com")

    assert "-dr" in command or "-disable-redirects" in command
