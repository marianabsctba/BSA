from app.assessment_engine import AssessmentEngine
from app.assessment_orchestrator import PROFILES, _deduplicate_findings
from app.assessment_registry import registry


def test_every_profile_engine_is_registered_and_mapped():
    profile_engines = {name for providers in PROFILES.values() for name in providers}
    assert profile_engines <= set(registry.providers)
    assert profile_engines <= set(AssessmentEngine.PROVIDERS)


def test_public_evidence_hides_nested_engine_identity():
    engine = AssessmentEngine()
    engine.add_provider_result(
        "nuclei",
        "example.com",
        {
            "title": "Exposure evidence",
            "severity": "medium",
            "confidence": 80,
            "evidence": {
                "nested": {
                    "provider": "internal-provider",
                    "tool_name": "internal-tool",
                    "value": "kept",
                }
            },
        },
    )
    evidence = engine.export_public()["findings"][0]["evidence"]
    assert evidence["nested"]["value"] == "kept"
    assert "provider" not in evidence["nested"]
    assert "tool_name" not in evidence["nested"]


def test_duplicate_evidence_is_corroborated_not_repeated():
    rows = [
        {
            "asset": "api.example.com",
            "category": "external_discovery",
            "title": "External asset discovered",
            "severity": "info",
            "confidence": 80,
            "evidence": {"relationship": "subdomain"},
        },
        {
            "asset": "api.example.com.",
            "category": "external_discovery",
            "title": "External asset discovered",
            "severity": "info",
            "confidence": 85,
            "evidence": {"relationship": "subdomain"},
        },
    ]
    deduped, duplicate_count = _deduplicate_findings(rows)
    assert duplicate_count == 1
    assert len(deduped) == 1
    assert deduped[0]["confidence"] == 85
    assert deduped[0]["evidence"]["corroboration_count"] == 2
    assert deduped[0]["evidence"]["corroborated"] is True
    assert deduped[0]["evidence"]["independent_source_count"] == 0
    assert deduped[0]["evidence"]["independently_corroborated"] is False


def test_same_cve_from_multiple_engines_is_one_finding():
    rows = [
        {
            "asset": "api.example.local",
            "category": "vulnerability_validation",
            "title": "First engine title",
            "severity": "high",
            "confidence": 90,
            "evidence": {
                "asset": "api.example.local",
                "vulnerability_id": "CVE-2026-1234",
                "validation_state": "confirmed_evidence",
                "reference": ["ref-a"],
            },
        },
        {
            "asset": "api.example.local",
            "category": "web_assessment",
            "title": "Different engine title",
            "severity": "critical",
            "confidence": 88,
            "evidence": {
                "asset": "api.example.local",
                "vulnerability_id": "CVE-2026-1234",
                "validation_state": "needs_validation",
                "reference": ["ref-b"],
            },
        },
    ]
    deduped, duplicate_count = _deduplicate_findings(rows)
    assert duplicate_count == 1
    assert len(deduped) == 1
    finding = deduped[0]
    assert finding["severity"] == "critical"
    assert finding["evidence"]["corroboration_count"] == 2
    assert finding["evidence"]["validation_state"] == "confirmed_evidence"
    assert len(finding["evidence"]["references"]) == 2


def test_same_cve_from_multiple_engines_is_deduplicated():
    rows = [
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "Scanner A title",
            "severity": "high",
            "confidence": 90,
            "evidence": {
                "vulnerability_id": "CVE-2026-1234",
                "matched_at": "https://api.example.com/login",
                "relationship": "vulnerability-validation",
                "reference": ["ref-a"],
            },
        },
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "Scanner B title",
            "severity": "critical",
            "confidence": 92,
            "evidence": {
                "vulnerability_id": "CVE-2026-1234",
                "matched_at": "https://api.example.com/login",
                "relationship": "vulnerability-assessment",
                "reference": ["ref-b"],
            },
        },
    ]
    deduped, duplicate_count = _deduplicate_findings(rows)
    assert duplicate_count == 1
    assert len(deduped) == 1
    assert deduped[0]["severity"] == "critical"
    assert deduped[0]["evidence"]["corroboration_count"] == 2
    assert sorted(deduped[0]["evidence"]["references"]) == ["ref-a", "ref-b"]


def test_distinct_web_findings_are_not_collapsed():
    rows = [
        {
            "asset": "app.example.com",
            "category": "web_assessment",
            "title": "Missing CSP",
            "severity": "low",
            "confidence": 80,
            "evidence": {"url": "https://app.example.com", "cwe": "693", "relationship": "web-assessment"},
        },
        {
            "asset": "app.example.com",
            "category": "web_assessment",
            "title": "Cookie without Secure",
            "severity": "low",
            "confidence": 80,
            "evidence": {"url": "https://app.example.com", "cwe": "614", "relationship": "web-assessment"},
        },
    ]
    deduped, duplicate_count = _deduplicate_findings(rows)
    assert duplicate_count == 0
    assert len(deduped) == 2


def test_profile_health_requires_full_core_capability_coverage(monkeypatch):
    from app.engine_health import engine_health

    monkeypatch.setattr(
        "app.engine_health.registry.available",
        lambda name, target=None: name == "httpx",
    )
    monkeypatch.setattr(
        "app.engine_health.registry.capability_health",
        lambda target=None, capabilities=None: [
            {"name": "fingerprint", "operational": True},
            {"name": "certificate_intelligence", "operational": False},
            {"name": "vulnerability", "operational": False},
        ] if capabilities == ("fingerprint", "certificate_intelligence", "vulnerability") else [
            {"name": name, "operational": False} for name in (capabilities or ())
        ],
    )
    health = engine_health("example.com")
    rapid = health["profiles"]["rapid"]

    assert rapid["available_engines"] == 1
    assert rapid["requested_engines"] == 3
    assert rapid["coverage_percent"] == 33
    assert rapid["state"] == "partial"
    assert rapid["ready"] is False


def test_partial_coverage_is_true_when_provider_errors(monkeypatch):
    from app.assessment_orchestrator import run_assessment

    monkeypatch.setattr("app.assessment_orchestrator.PROFILES", {"rapid": ("httpx",)})
    monkeypatch.setattr("app.assessment_orchestrator.PROFILE_CAPABILITIES", {"rapid": ("fingerprint",)})
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)

    def boom(name, *, target):
        raise RuntimeError("boom")

    monkeypatch.setattr("app.assessment_orchestrator.registry.execute", boom)

    result = run_assessment("example.com", profile="rapid")
    assert result["public"]["partial_coverage"] is True
    assert result["internal"]["errors"]



def test_independent_backend_corroboration_boosts_confidence():
    rows = [
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "CVE evidence",
            "severity": "high",
            "confidence": 88,
            "_source_backend": "backend-a",
            "evidence": {
                "vulnerability_id": "CVE-2026-5555",
                "matched_at": "https://api.example.com/login",
            },
        },
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "Same CVE evidence",
            "severity": "high",
            "confidence": 90,
            "_source_backend": "backend-b",
            "evidence": {
                "vulnerability_id": "CVE-2026-5555",
                "matched_at": "https://api.example.com/login",
            },
        },
    ]

    deduped, duplicate_count = _deduplicate_findings(rows)

    assert duplicate_count == 1
    assert len(deduped) == 1
    finding = deduped[0]
    assert finding["confidence"] == 94
    assert finding["evidence"]["independent_source_count"] == 2
    assert finding["evidence"]["independently_corroborated"] is True
    assert "_source_backend" not in finding
    assert "_source_backends" not in finding


def test_duplicate_from_same_backend_does_not_fake_independent_corroboration():
    rows = [
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "CVE evidence",
            "severity": "high",
            "confidence": 88,
            "_source_backend": "backend-a",
            "evidence": {"vulnerability_id": "CVE-2026-7777"},
        },
        {
            "asset": "api.example.com",
            "category": "vulnerability",
            "title": "CVE evidence repeated",
            "severity": "high",
            "confidence": 90,
            "_source_backend": "backend-a",
            "evidence": {"vulnerability_id": "CVE-2026-7777"},
        },
    ]

    deduped, _ = _deduplicate_findings(rows)
    finding = deduped[0]

    assert finding["confidence"] == 90
    assert finding["evidence"]["independent_source_count"] == 1
    assert finding["evidence"]["independently_corroborated"] is False


def test_first_pass_out_of_scope_evidence_is_never_registered(monkeypatch):
    from app.assessment_orchestrator import run_assessment
    from app.assessment_providers import ProviderResult

    monkeypatch.setattr("app.assessment_orchestrator.PROFILES", {"rapid": ("httpx",)})
    monkeypatch.setattr("app.assessment_orchestrator.PROFILE_CAPABILITIES", {"rapid": ("fingerprint",)})
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)
    monkeypatch.setattr(
        "app.assessment_orchestrator.registry.execute",
        lambda name, *, target: [
            ProviderResult(
                "Outside evidence",
                "info",
                90,
                {"asset": "outside.example.net", "status_code": 200},
            )
        ],
    )

    result = run_assessment(
        "example.com",
        profile="rapid",
        authorize=lambda value: value == "example.com",
    )

    assert result["public"]["finding_count"] == 0
    assert result["internal"]["scope_filtered"] == 1


def test_balanced_defers_active_web_checks_until_http_validation(monkeypatch):
    from app.assessment_orchestrator import run_assessment
    from app.assessment_providers import ProviderResult

    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILES",
        {"balanced": ("httpx", "nuclei", "zap")},
    )
    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILE_CAPABILITIES",
        {"balanced": ("fingerprint", "vulnerability", "web_assessment")},
    )
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)

    calls = []

    def execute(name, *, target):
        calls.append((name, target))
        if name == "httpx":
            return [
                ProviderResult(
                    "HTTP validated",
                    "info",
                    95,
                    {"url": "https://example.com", "status_code": 200},
                )
            ]
        if name == "nuclei":
            return [
                ProviderResult(
                    "Evidence",
                    "high",
                    90,
                    {
                        "url": target,
                        "vulnerability_id": "CVE-2026-9999",
                        "validation_state": "confirmed_evidence",
                    },
                )
            ]
        return []

    monkeypatch.setattr("app.assessment_orchestrator.registry.execute", execute)

    result = run_assessment(
        "example.com",
        profile="balanced",
        authorize=lambda value: value in {"example.com", "https://example.com"},
    )

    assert calls.count(("nuclei", "https://example.com")) == 1
    assert not any(name == "nuclei" and target == "example.com" for name, target in calls)
    assert "nuclei" in result["internal"]["deferred"]
    assert result["public"]["coverage"]["capability_coverage_percent"] == 100



def test_assessment_budget_limits_followups_and_marks_partial(monkeypatch):
    from app.assessment_orchestrator import run_assessment
    from app.assessment_providers import ProviderResult

    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILES",
        {"surface": ("subfinder",)},
    )
    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILE_CAPABILITIES",
        {"surface": ("discovery",)},
    )
    monkeypatch.setenv("BSA_ASSESSMENT_MAX_FOLLOWUPS", "1")
    monkeypatch.setenv("BSA_ASSESSMENT_MAX_FINDINGS", "50")
    monkeypatch.setenv("BSA_ASSESSMENT_BUDGET_SECONDS", "30")
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)
    monkeypatch.setattr(
        "app.assessment_orchestrator.registry.capability_health",
        lambda target=None, capabilities=None: [
            {"name": "discovery", "operational": True, "status": "ready"}
        ],
    )

    calls = []

    def execute(name, *, target):
        calls.append((name, target))
        if name == "subfinder":
            return [
                ProviderResult("child", "info", 80, {"asset": "a.example.org"}),
                ProviderResult("child", "info", 80, {"asset": "b.example.org"}),
            ]
        return []

    monkeypatch.setattr("app.assessment_orchestrator.registry.execute", execute)

    result = run_assessment(
        "example.org",
        profile="surface",
        authorize=lambda value: value.endswith("example.org"),
    )

    assert result["public"]["coverage"]["followup_targets"] == 1
    assert result["public"]["coverage"]["provider_calls"] >= 1
    assert result["public"]["coverage"]["execution_ms"] >= 0



def test_balanced_core_coverage_ignores_optional_external_enrichment(monkeypatch):
    from app.assessment_orchestrator import run_assessment

    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILES",
        {"balanced": ("httpx",)},
    )
    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILE_CAPABILITIES",
        {"balanced": ("fingerprint", "credential_exposure", "intelligence")},
    )
    monkeypatch.setattr(
        "app.assessment_orchestrator.PROFILE_OPTIONAL_CAPABILITIES",
        {"balanced": ("credential_exposure", "intelligence")},
    )
    monkeypatch.setattr("app.assessment_orchestrator.registry.available", lambda name, target=None: True)
    monkeypatch.setattr("app.assessment_orchestrator.registry.execute", lambda name, *, target: [])
    monkeypatch.setattr(
        "app.assessment_orchestrator.registry.capability_health",
        lambda target=None, capabilities=None: [
            {"name": "fingerprint", "operational": True, "status": "ready"},
            {"name": "credential_exposure", "operational": False, "status": "unavailable"},
            {"name": "intelligence", "operational": False, "status": "unavailable"},
        ],
    )

    result = run_assessment("example.org", profile="balanced")

    assert result["public"]["partial_coverage"] is False
    assert result["public"]["coverage"]["requested_capabilities"] == 1
    assert result["public"]["coverage"]["operational_capabilities"] == 1
    assert result["public"]["coverage"]["capability_coverage_percent"] == 100
    assert result["public"]["coverage"]["optional_capabilities"] == 2
    assert result["public"]["coverage"]["optional_operational_capabilities"] == 0
    assert result["public"]["optional_capabilities"] == [
        "credential_exposure",
        "intelligence",
    ]



def test_balanced_health_does_not_require_optional_external_enrichments(monkeypatch):
    from app.engine_health import engine_health

    monkeypatch.setattr("app.engine_health.registry.available", lambda name, target=None: False)

    def capability_health(target=None, capabilities=None):
        rows = []
        for name in capabilities or ():
            rows.append(
                {
                    "name": name,
                    "operational": name not in {"credential_exposure", "intelligence"},
                }
            )
        return rows

    monkeypatch.setattr("app.engine_health.registry.capability_health", capability_health)

    health = engine_health("example.org")
    balanced = health["profiles"]["balanced"]

    assert balanced["ready"] is True
    assert balanced["state"] == "ready"
    assert balanced["coverage_percent"] == 100
    assert balanced["optional_capabilities"] == 2
    assert balanced["optional_operational_capabilities"] == 0



def test_credentialed_external_providers_never_define_core_readiness():
    from app.assessment_orchestrator import PROFILE_CAPABILITIES, PROFILE_OPTIONAL_CAPABILITIES
    from app.assessment_registry import EXTERNAL_CREDENTIAL_PROVIDERS, registry

    credentialed_capabilities = {
        capability
        for capability, providers in registry.CAPABILITY_PROVIDERS.items()
        if set(providers) & set(EXTERNAL_CREDENTIAL_PROVIDERS)
    }

    for profile, capabilities in PROFILE_CAPABILITIES.items():
        optional = set(PROFILE_OPTIONAL_CAPABILITIES.get(profile, ()))
        assert credentialed_capabilities.intersection(capabilities) <= optional
