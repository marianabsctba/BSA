from app.models import Finding, Severity
from app.scoring import exposure_score


def test_score_penalizes_open_findings_by_severity_and_confidence():
    findings = [
        Finding(
            id="f1",
            asset_id="a1",
            title="Exposure",
            severity=Severity.HIGH,
            confidence=100,
            evidence="Observed",
        ),
        Finding(
            id="f2",
            asset_id="a1",
            title="Weak signal",
            severity=Severity.MEDIUM,
            confidence=50,
            evidence="Observed",
        ),
    ]
    result = exposure_score(findings)
    assert result.score == 82
    assert result.penalty == 18
    assert len(result.rationale) == 2
