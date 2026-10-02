from app.assessment_engine import AssessmentEngine


def test_confirmed_evidence_is_strong():
    engine = AssessmentEngine()
    engine.add_provider_result(
        "nuclei",
        "api.example.com",
        {
            "title": "Confirmed exposure",
            "severity": "high",
            "confidence": 92,
            "evidence": {
                "vulnerability_id": "CVE-2026-4242",
                "validation_state": "confirmed_evidence",
                "matched_at": "https://api.example.com/login",
            },
        },
    )

    finding = engine.export_public()["findings"][0]
    assert finding["evidence_state"] == "confirmed_evidence"
    assert finding["evidence_quality"] == "strong"
    assert finding["evidence"]["validation_state"] == "confirmed_evidence"


def test_active_security_finding_defaults_to_needs_validation():
    engine = AssessmentEngine()
    engine.add_provider_result(
        "zap",
        "https://app.example.com",
        {
            "title": "Possible web issue",
            "severity": "medium",
            "confidence": 78,
            "evidence": {"url": "https://app.example.com"},
        },
    )

    finding = engine.export_public()["findings"][0]
    assert finding["evidence_state"] == "needs_validation"
    assert finding["evidence_quality"] == "moderate"


def test_discovery_observation_is_not_mislabeled_as_vulnerability():
    engine = AssessmentEngine()
    engine.add_provider_result(
        "subfinder",
        "www.example.com",
        {
            "title": "Subdomain observed",
            "severity": "info",
            "confidence": 85,
            "evidence": {"relationship": "subdomain"},
        },
    )

    finding = engine.export_public()["findings"][0]
    assert finding["evidence_state"] == "observed"
    assert finding["evidence_quality"] == "strong"


def test_evidence_classification_does_not_leak_backend_or_secret():
    engine = AssessmentEngine()
    engine.add_provider_result(
        "nuclei",
        "example.com",
        {
            "title": "Exposure",
            "severity": "high",
            "confidence": 90,
            "evidence": {
                "provider": "private-engine",
                "token": "super-secret-token",
                "validation_state": "confirmed_evidence",
            },
        },
    )

    finding = engine.export_public()["findings"][0]
    serialized = str(finding)
    assert "private-engine" not in serialized
    assert "super-secret-token" not in serialized
    assert finding["evidence"]["token"] == "[REDACTED]"
