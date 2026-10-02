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
