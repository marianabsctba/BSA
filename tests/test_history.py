from app.history import change_summary, record_observations


class Asset:
    def __init__(self, fingerprint, confidence, evidence_count, sources, tags, evidence_refs=()):
        self.fingerprint = fingerprint
        self.confidence = confidence
        self.evidence_count = evidence_count
        self.sources = tuple(sources)
        self.tags = tuple(tags)
        self.evidence_refs = tuple(evidence_refs)


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


def test_lifecycle_is_tenant_scoped_and_persists_evidence_refs(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "history.db"))
    a=Asset("shared-fp",90,2,["dns"],["internet-facing"],["dns:a:example.org"])
    first=history.record_lifecycle([a],[{"kind":"a","value":"203.0.113.10","subject":"example.org"}],"tenant-a")
    second=history.record_lifecycle([a],[{"kind":"a","value":"203.0.113.11","subject":"example.org"}],"tenant-b")
    assert history.lifecycle_for("shared-fp","tenant-a")["observations"] == 1
    assert history.lifecycle_for("shared-fp","tenant-b")["observations"] == 1
    assert first[0]["evidence_refs"] == ["dns:a:example.org"]
