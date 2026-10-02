from app.assessment_providers import NucleiProvider, PureDnsProvider


def test_nuclei_requires_controlled_template_directory(monkeypatch, tmp_path):
    monkeypatch.setattr("app.assessment_providers.shutil.which", lambda name: f"/usr/local/bin/{name}")
    missing = tmp_path / "missing-templates"
    monkeypatch.setenv("BSA_NUCLEI_TEMPLATES", str(missing))
    provider = NucleiProvider()
    assert provider.available() is False

    templates = tmp_path / "nuclei-templates"
    templates.mkdir()
    monkeypatch.setenv("BSA_NUCLEI_TEMPLATES", str(templates))
    assert provider.available() is True
    command = provider._command("https://example.com")
    assert "-duc" in command
    assert "-t" in command
    assert str(templates) in command
    assert "-exclude-tags" in command


def test_puredns_requires_resolver_files(monkeypatch, tmp_path):
    monkeypatch.setattr("app.assessment_providers.shutil.which", lambda name: f"/usr/local/bin/{name}")

    resolvers = tmp_path / "resolvers.txt"
    trusted = tmp_path / "trusted.txt"
    monkeypatch.setenv("BSA_PUREDNS_RESOLVERS", str(resolvers))
    monkeypatch.setenv("BSA_PUREDNS_TRUSTED_RESOLVERS", str(trusted))

    provider = PureDnsProvider()
    assert provider.available() is False

    resolvers.write_text("1.1.1.1\n", encoding="utf-8")
    trusted.write_text("8.8.8.8\n", encoding="utf-8")
    assert provider.available() is True


def test_openvas_readiness_requires_live_configuration(monkeypatch, tmp_path):
    from app.assessment_providers import OpenVASProvider

    monkeypatch.setattr("app.assessment_providers.shutil.which", lambda name: "/usr/local/bin/gvm-cli" if name == "gvm-cli" else None)
    socket_path = tmp_path / "gvmd.sock"
    monkeypatch.setenv("BSA_GVM_SOCKET", str(socket_path))
    monkeypatch.setenv("BSA_GVM_SCAN_CONFIG_ID", "config-id")
    monkeypatch.setenv("BSA_GVM_SCANNER_ID", "scanner-id")

    provider = OpenVASProvider()
    state = provider.readiness()
    assert state["installed"] is True
    assert state["configured"] is True
    assert state["socket_ready"] is False
    assert state["ready"] is False


def test_public_engine_health_hides_engine_readiness_details(monkeypatch):
    from app.engine_health import public_engine_health

    monkeypatch.setattr("app.engine_health.engine_health", lambda target=None: {
        "available_count": 1,
        "engine_count": 2,
        "engines": [
            {"name": "private-a", "available": True, "readiness": {"installed": True, "configured": True, "ready": True}},
            {"name": "private-b", "available": False, "readiness": {"installed": True, "configured": False, "ready": False}},
        ],
        "profiles": {"rapid": {"ready": False, "state": "partial", "coverage_percent": 50}},
    })
    public = public_engine_health()
    assert "engines" not in public
    assert "private-a" not in str(public)
    assert "installed" not in str(public)



def test_openvas_optional_live_probe_controls_readiness(monkeypatch, tmp_path):
    from app.assessment_providers import OpenVASProvider

    socket_path = tmp_path / "gvmd.sock"
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        "app.assessment_providers.shutil.which",
        lambda name: "/usr/local/bin/gvm-cli" if name == "gvm-cli" else None,
    )
    monkeypatch.setenv("BSA_GVM_SOCKET", str(socket_path))
    monkeypatch.setenv("BSA_GVM_SCAN_CONFIG_ID", "config-id")
    monkeypatch.setenv("BSA_GVM_SCANNER_ID", "scanner-id")
    monkeypatch.setenv("BSA_GVM_READINESS_PROBE", "1")

    provider = OpenVASProvider()
    monkeypatch.setattr(provider, "_probe", lambda: False)
    state = provider.readiness()
    assert state["live_probe_enabled"] is True
    assert state["live"] is False
    assert state["ready"] is False

    monkeypatch.setattr(provider, "_probe", lambda: True)
    state = provider.readiness()
    assert state["live"] is True
    assert state["ready"] is True


def test_engine_runtime_readiness_contracts_hide_configuration_details(monkeypatch):
    from app.assessment_providers import SecretExposureProvider, TestSslProvider, ZAPProvider

    monkeypatch.setattr("app.assessment_providers.shutil.which", lambda name: f"/usr/local/bin/{name}")

    for provider in (SecretExposureProvider(), TestSslProvider(), ZAPProvider()):
        state = provider.readiness()
        assert state["installed"] is True
        assert state["ready"] is True
        assert "binary" not in state
        assert "path" not in state
