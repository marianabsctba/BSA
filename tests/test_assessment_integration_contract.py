from app.assessment_engine import AssessmentEngine
from app.assessment_orchestrator import PROFILES
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
