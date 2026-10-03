import json

from app import job_queue
from app.assessment_quality import latest_assessment_quality


def _configure(tmp_path,monkeypatch):
    monkeypatch.setenv("BSA_JOBS_DB",str(tmp_path/"jobs.db"))


def _insert_job(
    tenant_id: str,
    *,
    status: str,
    result: dict | None=None,
    profile: str="rapid",
    completed_at: int=100,
):
    conn=job_queue._db()
    conn.execute(
        """INSERT INTO assessment_jobs(
            job_id,tenant_id,user_id,email,role,name,target,profile,
            authorization_ref,status,created_at,completed_at,result_json,job_type
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            f"job-{tenant_id}-{status}-{completed_at}",tenant_id,"user","u@example.com",
            "analyst","User","example.org",profile,"auth",status,1,completed_at,
            json.dumps(result) if result is not None else None,"assessment",
        ),
    )
    conn.commit()
    conn.close()


def _result(*,findings: int, partial: bool, success: int, exercised: int):
    return {
        "finding_count":findings,
        "partial_coverage":partial,
        "coverage":{
            "requested_capabilities":3,
            "operational_capabilities":3 if not partial else 2,
            "capability_coverage_percent":100 if not partial else 67,
            "budget_exhausted":False,
            "provider_calls":3,
            "effectiveness":{
                "execution_success_percent":success,
                "exercised_capability_percent":exercised,
                "productive_capability_percent":0,
                "evidenced_finding_percent":0,
                "high_confidence_finding_percent":0,
                "confirmed_evidence_count":0,
                "independently_corroborated_count":0,
                "successful_calls":3 if success==100 else 2,
                "failed_calls":0 if success==100 else 1,
            },
        },
    }


def test_quality_reports_never_run(tmp_path,monkeypatch):
    _configure(tmp_path,monkeypatch)
    quality=latest_assessment_quality("tenant-a")
    assert quality["state"]=="never_run"
    assert quality["zero_findings_interpretable"] is False


def test_quality_allows_zero_findings_only_after_complete_execution(tmp_path,monkeypatch):
    _configure(tmp_path,monkeypatch)
    _insert_job(
        "tenant-a",
        status="succeeded",
        result=_result(findings=0,partial=False,success=100,exercised=100),
    )
    quality=latest_assessment_quality("tenant-a")
    assert quality["state"]=="complete"
    assert quality["finding_count"]==0
    assert quality["zero_findings_interpretable"] is True


def test_quality_marks_zero_findings_inconclusive_when_execution_is_partial(tmp_path,monkeypatch):
    _configure(tmp_path,monkeypatch)
    _insert_job(
        "tenant-a",
        status="succeeded",
        result=_result(findings=0,partial=True,success=67,exercised=67),
    )
    quality=latest_assessment_quality("tenant-a")
    assert quality["state"]=="partial"
    assert quality["finding_count"]==0
    assert quality["zero_findings_interpretable"] is False
    assert "incomplete" in quality["interpretation"]


def test_quality_marks_failed_assessment_as_non_interpretable(tmp_path,monkeypatch):
    _configure(tmp_path,monkeypatch)
    _insert_job("tenant-a",status="failed",result=None)
    quality=latest_assessment_quality("tenant-a")
    assert quality["state"]=="failed"
    assert quality["zero_findings_interpretable"] is False
