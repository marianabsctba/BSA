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

def test_discovery_run_diff_tracks_added_removed_and_changed(tmp_path, monkeypatch):
    from app import history
    from types import SimpleNamespace
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "diff.db"))
    a=SimpleNamespace(fingerprint="a",value="a.example.org",asset_type="subdomain",confidence=90)
    b=SimpleNamespace(fingerprint="b",value="b.example.org",asset_type="subdomain",confidence=80)
    first=history.record_discovery_run([a,b],[], "tenant-diff","run-1")
    assert first["summary"]["added"] == 2
    c_asset=SimpleNamespace(fingerprint="c",value="c.example.org",asset_type="subdomain",confidence=95)
    a_changed=SimpleNamespace(fingerprint="a",value="a.example.org",asset_type="subdomain",confidence=70)
    second=history.record_discovery_run([a_changed,c_asset],[], "tenant-diff","run-2")
    assert second["summary"]["added"] == 1
    assert second["summary"]["removed"] == 1
    assert second["summary"]["changed"] == 1

def test_diff_risk_context_adds_exposure_for_new_and_changed_assets():
    from app.history import diff_risk_context
    from types import SimpleNamespace
    from app.models import Finding, Severity
    a=SimpleNamespace(fingerprint="a",id="asset-a",value="api.example.org",criticality=5,
                      confidence=95,tags=["internet-facing","production"],type=SimpleNamespace(value="application"))
    finding=Finding(id="f",asset_id="asset-a",title="critical",severity=Severity.CRITICAL,confidence=95,evidence="e")
    diff={"added":[{"fingerprint":"a","value":"api.example.org"}],"removed":[],"changed":[]}
    out=diff_risk_context(diff,[a],[finding])
    assert out["added"][0]["exposure_score"] > 0
    assert out["added"][0]["exposure_band"] in {"low","medium","high","critical"}
