import subprocess

import pytest

from app import assessment_providers as providers
from app import security


class _Completed:
    stdout = ""
    stderr = ""
    returncode = 0


def test_nmap_uses_prevalidated_ip_instead_of_hostname(monkeypatch):
    monkeypatch.setattr(
        providers,
        "resolve_external_target",
        lambda target: security.ResolvedExternalTarget(
            host="example.org",
            url="https://example.org",
            ips=("203.0.113.25",),
        ),
    )
    monkeypatch.setattr(providers, "revalidate_external_resolution", lambda snapshot: snapshot.ips)
    monkeypatch.setattr(providers.NmapProvider, "available", lambda self: True)

    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return _Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)
    providers.NmapProvider().execute("example.org")

    assert seen["command"][-1] == "203.0.113.25"
    assert "example.org" not in seen["command"]


def test_naabu_uses_prevalidated_ip_instead_of_hostname(monkeypatch):
    monkeypatch.setattr(
        providers,
        "resolve_external_target",
        lambda target: security.ResolvedExternalTarget(
            host="example.org",
            url="https://example.org",
            ips=("203.0.113.26",),
        ),
    )
    monkeypatch.setattr(providers, "revalidate_external_resolution", lambda snapshot: snapshot.ips)
    monkeypatch.setattr(providers.PortExposureProvider, "available", lambda self: True)

    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        return _Completed()

    monkeypatch.setattr(subprocess, "run", fake_run)
    providers.PortExposureProvider().execute("example.org")

    host_index = seen["command"].index("-host") + 1
    assert seen["command"][host_index] == "203.0.113.26"
    assert "example.org" not in seen["command"]


def test_command_provider_rejects_resolution_that_rebinds_private(monkeypatch):
    class Probe(providers.CommandProvider):
        binary = "probe"
        def _command(self, target):
            return ["probe", target]

    monkeypatch.setattr(Probe, "available", lambda self: True)
    monkeypatch.setattr(
        providers,
        "resolve_external_target",
        lambda target: security.ResolvedExternalTarget(
            host="example.org",
            url="https://example.org",
            ips=("203.0.113.27",),
        ),
    )

    def reject_rebind(snapshot):
        raise ValueError("target resolves to non-public address")

    monkeypatch.setattr(providers, "revalidate_external_resolution", reject_rebind)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _Completed())

    with pytest.raises(ValueError, match="non-public"):
        Probe().execute("example.org")
