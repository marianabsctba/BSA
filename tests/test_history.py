from types import SimpleNamespace
from app.history import change_summary, record_observations
from types import SimpleNamespace


class Asset:
    def __init__(self, fingerprint, confidence, evidence_count, sources, tags, evidence_refs=()):
        self.fingerprint = fingerprint
        self.confidence = confidence
        self.evidence_count = evidence_count
        self.sources = tuple(sources)
        self.tags = tuple(tags)
        self.evidence_refs = tuple(evidence_refs)
        self.value = fingerprint
        self.asset_type = "application"


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
    a=SimpleNamespace(fingerprint="a",value="a.example.org",asset_type="subdomain",confidence=90,evidence_refs=[])
    b=SimpleNamespace(fingerprint="b",value="b.example.org",asset_type="subdomain",confidence=80,evidence_refs=[])
    first=history.record_discovery_run([a,b],[], "tenant-diff","run-1")
    assert first["summary"]["added"] == 2
    c_asset=SimpleNamespace(fingerprint="c",value="c.example.org",asset_type="subdomain",confidence=95,evidence_refs=[])
    a_changed=SimpleNamespace(fingerprint="a",value="a.example.org",asset_type="subdomain",confidence=70,evidence_refs=[])
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

def test_diff_risk_context_adds_risk_delta_for_new_asset():
    from app.history import diff_risk_context
    from types import SimpleNamespace
    from app.models import Severity
    asset=SimpleNamespace(fingerprint="r",id="asset-r",value="api.example.org",
        criticality=5,confidence=95,tags=["internet-facing","production"],
        type=SimpleNamespace(value="application"))
    finding=SimpleNamespace(asset_id="asset-r",status="open",confidence=95,
        cvss=9.8,epss=0.95,kev=True,exploit_available=True,cpe="cpe:2.3:a:vendor:app:1:*:*:*:*:*:*:*",
        vulnerability_id="CVE-TEST",false_positive_confidence=0)
    finding.severity=Severity.CRITICAL
    diff={"added":[{"fingerprint":"r","value":"api.example.org"}],"removed":[],"changed":[]}
    out=diff_risk_context(diff,[asset],[finding])
    assert out["risk_context"]["new_risk"] > 0
    assert out["added"][0]["risk_band"] in {"low","medium","high","critical"}

def test_surface_change_ctem_prioritization_requires_evidence():
    from app.risk_engine import prioritize_surface_change
    change={"fingerprint":"x","reasons":["certificate_name"],"evidence_refs":["ct:cert:x"],
            "exposure_score":80,"risk_score":0,"rationale":["exposição direta à Internet"]}
    asset=SimpleNamespace(id="asset-x",criticality=4,confidence=90,tags=["internet-facing"],
                          type=SimpleNamespace(value="application"))
    out=prioritize_surface_change(change,asset,[])
    assert out["state"] == "prioritized"
    assert out["priority"] == 80
    assert out["action"] == "expedite"

def test_surface_change_without_evidence_is_not_prioritized():
    from app.risk_engine import prioritize_surface_change
    asset=SimpleNamespace(id="asset-x",criticality=4,confidence=90,tags=[],type=SimpleNamespace(value="application"))
    out=prioritize_surface_change({"fingerprint":"x","exposure_score":90},asset,[])
    assert out["state"] == "insufficient_evidence"
    assert out["priority"] == 0

def test_ctem_queue_has_controlled_state_transitions_and_tenant_isolation(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "ctem.db"))
    item=history.upsert_ctem_item({
        "asset_id":"asset-1","finding_id":"finding-1","priority":90,"action":"immediate",
        "title":"Critical exposed service","drivers":["KEV"],"evidence_refs":["e:1"]},"tenant-a")
    assert item["state"] == "new"
    history.update_ctem_state(item["item_id"],"tenant-a","acknowledged")
    history.update_ctem_state(item["item_id"],"tenant-a","in_progress")
    history.update_ctem_state(item["item_id"],"tenant-a","resolved")
    done=history.update_ctem_state(item["item_id"],"tenant-a","verified")
    assert done["state"] == "verified"
    assert history.list_ctem_items("tenant-b") == []
    try:
        history.update_ctem_state(item["item_id"],"tenant-a","new")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid backward CTEM transition was accepted")

def test_materialize_ctem_from_evidence_backed_surface_diff(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "ctem-materialize.db"))
    asset=SimpleNamespace(id="asset-1",fingerprint="fp-1",criticality=5,confidence=95,
        tags=["internet-facing","production"],type=SimpleNamespace(value="application"))
    finding=SimpleNamespace(asset_id="asset-1",status="open",confidence=95,cvss=9.8,epss=0.95,
        kev=True,exploit_available=True,cpe="cpe:2.3:a:v:p:1:*:*:*:*:*:*:*",
        vulnerability_id="CVE-TEST",false_positive_confidence=0)
    change={"fingerprint":"fp-1","evidence_refs":["ct:1"],"reasons":["certificate_name"],
            "exposure_score":90,"risk_score":0}
    out=history.materialize_ctem_from_diff({"added":[change],"changed":[]},[asset],[finding],"tenant-a")
    assert len(out) == 1
    assert out[0]["state"] == "new"
    assert out[0]["priority"] >= 90
    assert history.list_ctem_items("tenant-b") == []

def test_ctem_verification_requires_evidence_and_reopens_on_failed_retest(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "verify.db"))
    item=history.upsert_ctem_item({"asset_id":"a","priority":90,"action":"immediate","title":"x",
        "drivers":["exposure"],"evidence_refs":["e:1"]},"tenant-v")
    history.update_ctem_state(item["item_id"],"tenant-v","acknowledged")
    history.update_ctem_state(item["item_id"],"tenant-v","in_progress")
    history.update_ctem_state(item["item_id"],"tenant-v","resolved")
    try:
        history.verify_ctem_item(item["item_id"],"tenant-v","passed",[])
    except ValueError:
        pass
    else:
        raise AssertionError("verification without evidence was accepted")
    failed=history.verify_ctem_item(item["item_id"],"tenant-v","failed",["retest:1"],"condition still present")
    assert failed["state"] == "in_progress"
    history.update_ctem_state(item["item_id"],"tenant-v","resolved")
    passed=history.verify_ctem_item(item["item_id"],"tenant-v","passed",["retest:2"],"condition removed")
    assert passed["state"] == "verified"


def test_materialize_ctem_applies_relevant_attack_path_context(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "ctem-path.db"))
    asset=SimpleNamespace(id="asset-1",fingerprint="fp-1",criticality=4,confidence=95,
        tags=["internet-facing"],type=SimpleNamespace(value="application"))
    change={"fingerprint":"fp-1","evidence_refs":["asset:e1"],"reasons":["surface"],
            "exposure_score":70,"risk_score":70}
    out=history.materialize_ctem_from_diff(
        {"added":[change],"changed":[]},[asset],[],"tenant-path",
        [{"nodes":["internet","asset-1","finding-1"],"score":90}],
    )
    assert len(out)==1
    assert out[0]["priority"]==85
    assert out[0]["attack_path_count"]==1
    assert out[0]["action"]=="immediate"

def test_materialize_ctem_carries_remediation_leverage(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "ctem-leverage.db"))
    asset=SimpleNamespace(id="asset-1",fingerprint="fp-1",criticality=4,confidence=95,
        tags=["internet-facing"],type=SimpleNamespace(value="application"))
    change={"fingerprint":"fp-1","evidence_refs":["asset:e1"],"reasons":["surface"],
            "exposure_score":70,"risk_score":70}
    out=history.materialize_ctem_from_diff(
        {"added":[change],"changed":[]},[asset],[],"tenant-leverage",
        remediation_leverage={"asset-1":{"leverage_score":88,"paths_affected":3,
            "reduction_percent":62,"path_coverage_percent":75}},
    )
    assert out[0]["leverage_score"] == 88
    assert out[0]["paths_affected"] == 3
    assert out[0]["risk_reduction_percent"] == 62
    assert "alto potencial de redução de risco" in out[0]["drivers"]

def test_ctem_leverage_summary_ignores_verified_and_aggregates_active_items():
    from app.history import ctem_leverage_summary
    items=[
      {"state":"new","leverage_score":90,"paths_affected":3,"risk_reduction_percent":60},
      {"state":"in_progress","leverage_score":70,"paths_affected":1,"risk_reduction_percent":20},
      {"state":"verified","leverage_score":100,"paths_affected":9,"risk_reduction_percent":90},
    ]
    out=ctem_leverage_summary(items)
    assert out["active_items"] == 2
    assert out["high_leverage_items"] == 1
    assert out["paths_affected"] == 4
    assert out["weighted_risk_reduction"] == 50

def test_ctem_operations_summary_uses_tenant_scoped_queue(tmp_path, monkeypatch):
    from app import history
    monkeypatch.setenv("BSA_HISTORY_DB", str(tmp_path / "ops.db"))
    history.upsert_ctem_item({"asset_id":"a","priority":90,"action":"immediate",
        "title":"high leverage","drivers":[],"evidence_refs":[],"leverage_score":90,
        "paths_affected":3,"risk_reduction_percent":60},"tenant-ops")
    items=history.list_ctem_items("tenant-ops")
    summary=history.ctem_leverage_summary(items)
    assert summary["active_items"] == 1
    assert summary["high_leverage_items"] == 1
    assert history.list_ctem_items("other-tenant") == []

def test_ctem_operational_summary_tracks_sla_aging_without_time_flakiness():
    from app.history import ctem_operational_summary
    from datetime import datetime, timezone, timedelta
    now=datetime(2026,10,1,12,0,tzinfo=timezone.utc)
    items=[
      {"state":"new","priority":90,"created_at":"2026-09-30T10:00:00+00:00","leverage_score":90,"paths_affected":2,"risk_reduction_percent":50},
      {"state":"in_progress","priority":70,"created_at":"2026-09-29T10:00:00+00:00","leverage_score":60,"paths_affected":1,"risk_reduction_percent":20},
      {"state":"verified","priority":90,"created_at":"2026-09-20T10:00:00+00:00","leverage_score":100,"paths_affected":9,"risk_reduction_percent":90},
    ]
    out=ctem_operational_summary(items,now)
    assert out["active_items"]==2
    assert out["overdue_items"]==2
    assert out["oldest_active_age_hours"]==50

def test_ctem_remediation_evidence_keeps_before_after_provenance():
    from app.history import ctem_remediation_evidence
    item={"state":"in_progress","priority":85,"leverage_score":88,"paths_affected":3,
          "evidence_refs":["finding:e1"]}
    verification={"result":"passed","state":"verified","evidence_refs":["retest:e2"],
                  "verified_at":"2026-10-01T12:00:00+00:00"}
    out=ctem_remediation_evidence(item,verification)
    assert out["before"]["priority"]==85
    assert out["before"]["evidence_refs"]==["finding:e1"]
    assert out["after"]["evidence_refs"]==["retest:e2"]
    assert out["evidence_complete"] is True

def test_ctem_audit_timeline_is_chronological_and_evidence_linked():
    from app.history import ctem_audit_timeline
    item={"created_at":"2026-10-01T10:00:00+00:00","state":"in_progress",
          "priority":85,"evidence_refs":["finding:e1"]}
    verifications=[
      {"verified_at":"2026-10-01T12:00:00+00:00","result":"failed","state":"in_progress",
       "evidence_refs":["retest:e2"],"notes":"still exposed"},
      {"verified_at":"2026-10-01T14:00:00+00:00","result":"passed","state":"verified",
       "evidence_refs":["retest:e3"],"notes":"condition removed"},
    ]
    out=ctem_audit_timeline(item,verifications)
    assert [x["event"] for x in out]==["created","verification","verification"]
    assert out[-1]["result"]=="passed"
    assert out[-1]["evidence_refs"]==["retest:e3"]
