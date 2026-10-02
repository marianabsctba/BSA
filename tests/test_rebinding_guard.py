import app.assessment_orchestrator as orchestrator
import app.security as security


def test_execution_target_blocks_unpinned_hostname_provider_in_production(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(
        orchestrator,
        "validated_external_binding",
        lambda target: {"host":"example.org","origin":"https://example.org","approved_ips":("93.184.216.34",)},
    )
    assert orchestrator._execution_target("nuclei","example.org") is None
    assert orchestrator._execution_target("httpx","example.org") is None
    assert orchestrator._execution_target("safeweb","example.org")=="example.org"


def test_execution_target_pins_direct_ip_provider_in_production(monkeypatch):
    monkeypatch.setenv("BSA_ENV","production")
    monkeypatch.setattr(
        orchestrator,
        "validated_external_binding",
        lambda target: {"host":"example.org","origin":"https://example.org","approved_ips":("93.184.216.34","93.184.216.35")},
    )
    assert orchestrator._execution_target("nmap","example.org")=="93.184.216.34"
    assert orchestrator._execution_target("naabu","example.org")=="93.184.216.34"


def test_cgnat_is_not_public():
    assert security._public_ip("100.64.0.1") is False
    assert security._public_ip("100.127.255.254") is False
