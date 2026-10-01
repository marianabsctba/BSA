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
    assert deduped[0]["confidence"] > 85
    assert deduped[0]["evidence"]["corroboration_count"] == 2
    assert deduped[0]["evidence"]["corroborated"] is True
