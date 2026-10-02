import app.ctem_retest as retest


def test_retest_passes_only_with_complete_coverage_and_no_matching_exposure():
    item={"item_id":"item-a","asset_id":"asset-a","title":"TLS weak protocol","finding_id":None}
    result={
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
        "findings":[],
    }

    out=retest.classify_ctem_retest(item,result,job_id="job-a",target="app.example.com")

    assert out["outcome"]=="passed"
    assert out["coverage_percent"]==100
    assert out["matching_findings"]==0
    assert out["evidence_refs"]==["assessment-job:job-a:coverage:100"]


def test_retest_is_inconclusive_when_coverage_is_partial():
    item={"item_id":"item-a","asset_id":"asset-a","title":"TLS weak protocol"}
    result={
        "partial_coverage":True,
        "coverage":{"capability_coverage_percent":75},
        "findings":[],
    }

    out=retest.classify_ctem_retest(item,result,job_id="job-a",target="app.example.com")

    assert out["outcome"]=="inconclusive"
    assert out["partial_coverage"] is True
    assert "partial" in out["reason"]


def test_retest_fails_when_material_exposure_remains_on_same_target():
    item={
        "item_id":"item-a",
        "asset_id":"asset-a",
        "title":"Surface change requiring CTEM attention",
        "finding_id":None,
    }
    result={
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
        "findings":[{
            "asset":"app.example.com",
            "title":"Administrative service exposed",
            "severity":"high",
            "evidence":{"references":["evidence://retest/high-1"]},
        }],
    }

    out=retest.classify_ctem_retest(item,result,job_id="job-a",target="app.example.com")

    assert out["outcome"]=="failed"
    assert out["matching_findings"]==1
    assert "evidence://retest/high-1" in out["evidence_refs"]
    assert "assessment-job:job-a:coverage:100" in out["evidence_refs"]


def test_retest_with_specific_finding_id_ignores_unrelated_material_findings():
    item={
        "item_id":"item-a",
        "asset_id":"asset-a",
        "title":"Known exposure",
        "finding_id":"CVE-2026-1234",
    }
    result={
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
        "findings":[{
            "asset":"app.example.com",
            "title":"Different issue",
            "vulnerability_id":"CVE-2026-9999",
            "severity":"high",
            "evidence":{},
        }],
    }

    out=retest.classify_ctem_retest(item,result,job_id="job-a",target="app.example.com")

    assert out["outcome"]=="passed"
    assert out["matching_findings"]==0


def test_ctem_retest_linkage_is_tenant_scoped(tmp_path,monkeypatch):
    import app.history as history

    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    history.record_ctem_retest("job-a","tenant-a","item-a","rapid","auth-a")

    assert history.ctem_retest_for_job("job-a","tenant-a")["item_id"]=="item-a"
    assert history.ctem_retest_for_job("job-a","tenant-b") is None

    done=history.complete_ctem_retest(
        "job-a","tenant-a","inconclusive",["assessment-job:job-a:coverage:50"],
    )
    assert done["outcome"]=="inconclusive"
    assert done["status"]=="reconciled"
    assert done["evidence_refs"]==["assessment-job:job-a:coverage:50"]


def test_retest_matches_url_evidence_to_hostname_target():
    item={
        "item_id":"item-a",
        "asset_id":"asset-a",
        "title":"Surface change requiring CTEM attention",
        "finding_id":None,
    }
    result={
        "partial_coverage":False,
        "coverage":{"capability_coverage_percent":100},
        "findings":[{
            "title":"Exposed admin endpoint",
            "severity":"high",
            "evidence":{
                "matched_at":"https://app.example.com:443/admin",
                "references":["evidence://url-match"],
            },
        }],
    }

    out=retest.classify_ctem_retest(
        item,result,job_id="job-url",target="app.example.com",
    )

    assert out["outcome"]=="failed"
    assert "evidence://url-match" in out["evidence_refs"]


def test_retest_reconciliation_claim_is_atomic(tmp_path,monkeypatch):
    import app.history as history

    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    history.record_ctem_retest("job-race","tenant-a","item-a","rapid","auth-a")

    assert history.claim_ctem_retest_reconciliation("job-race","tenant-a") is True
    assert history.claim_ctem_retest_reconciliation("job-race","tenant-a") is False

    link=history.ctem_retest_for_job("job-race","tenant-a")
    assert link["status"]=="reconciling"

    history.release_ctem_retest_reconciliation("job-race","tenant-a")
    assert history.claim_ctem_retest_reconciliation("job-race","tenant-a") is True


def test_completed_retest_cannot_be_claimed_again(tmp_path,monkeypatch):
    import app.history as history

    monkeypatch.setenv("BSA_HISTORY_DB",str(tmp_path/"history.db"))
    history.record_ctem_retest("job-done","tenant-a","item-a","rapid","auth-a")
    assert history.claim_ctem_retest_reconciliation("job-done","tenant-a") is True
    done=history.complete_ctem_retest(
        "job-done","tenant-a","passed",["assessment-job:job-done:coverage:100"],
    )

    assert done["status"]=="reconciled"
    assert history.claim_ctem_retest_reconciliation("job-done","tenant-a") is False
