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


def test_engine_runtime_readiness_contracts_hide_configuration_details(monkeypatch):
    from app.assessment_providers import SecretExposureProvider, TestSslProvider, ZAPProvider

    monkeypatch.setattr("app.assessment_providers.shutil.which", lambda name: f"/usr/local/bin/{name}")

    for provider in (SecretExposureProvider(), TestSslProvider(), ZAPProvider()):
        state = provider.readiness()
        assert state["installed"] is True
        assert state["ready"] is True
        assert "binary" not in state
        assert "path" not in state


def test_capability_health_reports_backend_coverage_without_provider_names(monkeypatch):
    from app.assessment_registry import registry

    states={"httpx":True,"tlsx":False}
    monkeypatch.setattr(
        registry,
        "CAPABILITY_PROVIDERS",
        {"fingerprint":("httpx","tlsx")},
    )
    monkeypatch.setattr(
        registry,
        "available",
        lambda name,target=None: states[name],
    )

    rows=registry.capability_health(
        "example.com",
        ("fingerprint",),
    )

    assert rows==[{
        "name":"fingerprint",
        "status":"degraded",
        "operational":True,
        "available_backends":1,
        "backend_count":2,
        "backend_coverage_percent":50,
        "redundant_backends":0,
    }]
    serialized=str(rows)
    assert "httpx" not in serialized
    assert "tlsx" not in serialized


def test_profile_health_exposes_missing_and_degraded_capabilities(monkeypatch):
    from app.engine_health import engine_health

    monkeypatch.setattr(
        "app.engine_health.registry.available",
        lambda name,target=None: True,
    )
    monkeypatch.setattr(
        "app.engine_health.registry.capability_health",
        lambda target=None,capabilities=None: [
            {
                "name":"fingerprint",
                "operational":True,
                "status":"ready",
                "available_backends":1,
                "backend_count":1,
            },
            {
                "name":"certificate_intelligence",
                "operational":True,
                "status":"degraded",
                "available_backends":1,
                "backend_count":2,
            },
            {
                "name":"vulnerability",
                "operational":False,
                "status":"unavailable",
                "available_backends":0,
                "backend_count":1,
            },
        ] if capabilities==(
            "fingerprint",
            "certificate_intelligence",
            "vulnerability",
        ) else [
            {
                "name":name,
                "operational":False,
                "status":"unavailable",
                "available_backends":0,
                "backend_count":1,
            }
            for name in (capabilities or ())
        ],
    )

    rapid=engine_health("example.com")["profiles"]["rapid"]

    assert rapid["coverage_percent"]==67
    assert rapid["backend_coverage_percent"]==50
    assert rapid["missing_capabilities"]==["vulnerability"]
    assert rapid["degraded_capabilities"]==["certificate_intelligence"]
    assert rapid["ready"] is False
