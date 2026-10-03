from app import assessment_orchestrator as orchestrator


def test_adaptive_coverage_preserved_when_nothing_is_deferred():
    assert orchestrator._adaptive_coverage_preserved("rapid", [], set()) is True


def test_adaptive_coverage_preserved_when_deferred_capabilities_are_protected(monkeypatch):
    monkeypatch.setitem(
        orchestrator.PROFILE_CAPABILITIES,
        "rapid",
        ("fingerprint", "vulnerability"),
    )
    monkeypatch.setattr(
        orchestrator.registry,
        "CAPABILITY_PROVIDERS",
        {
            "fingerprint": ("backend-a", "backend-b"),
            "vulnerability": ("backend-c",),
        },
    )

    assert orchestrator._adaptive_coverage_preserved(
        "rapid",
        {"backend-a"},
        {"fingerprint"},
    ) is True


def test_adaptive_coverage_not_preserved_when_deferred_capability_is_unprotected(monkeypatch):
    monkeypatch.setitem(
        orchestrator.PROFILE_CAPABILITIES,
        "rapid",
        ("fingerprint", "vulnerability"),
    )
    monkeypatch.setattr(
        orchestrator.registry,
        "CAPABILITY_PROVIDERS",
        {
            "fingerprint": ("backend-a", "backend-b"),
            "vulnerability": ("backend-c",),
        },
    )

    assert orchestrator._adaptive_coverage_preserved(
        "rapid",
        {"backend-a"},
        set(),
    ) is False
