from app.history import change_summary, record_observations


class Asset:
    def __init__(self, fingerprint, confidence, evidence_count, sources, tags):
        self.fingerprint = fingerprint
        self.confidence = confidence
        self.evidence_count = evidence_count
        self.sources = tuple(sources)
        self.tags = tuple(tags)


def test_history_detects_source_and_confidence_changes():
    fp = "test-change-asset"
    record_observations([Asset(fp, 80, 1, ["dns"], ["web-exposed"])])
    record_observations([Asset(fp, 95, 2, ["dns", "http"], ["web-exposed", "new"])])
    result = change_summary(fp)
    assert result["state"] == "changed"
    kinds = {x["kind"] for x in result["changes"]}
    assert "confidence_change" in kinds
    assert "evidence_change" in kinds
    assert "source_added" in kinds
    assert "tag_added" in kinds
