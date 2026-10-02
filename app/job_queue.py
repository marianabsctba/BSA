import json
import os
import sqlite3
import time
import uuid
from pathlib import Path


def _db_path() -> str:
    path=os.getenv("BSA_JOBS_DB","").strip()
    if path:
        return path
    if os.getenv("BSA_ENV","development").lower() in {"production","prod"}:
        return "/data/bsa_jobs.db"
    return str(Path("/tmp")/"bsa_jobs.db")


def _db():
    path=_db_path()
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(path,timeout=15)
    conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS assessment_jobs(
        job_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT NOT NULL,
        target TEXT NOT NULL,
        profile TEXT NOT NULL,
        authorization_ref TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        started_at INTEGER,
        completed_at INTEGER,
        result_json TEXT,
        error TEXT,
        materialized INTEGER NOT NULL DEFAULT 0
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_assessment_jobs_tenant_status ON assessment_jobs(tenant_id,status,created_at)")
    conn.commit()
    return conn


def enqueue_assessment(principal,target:str,profile:str,authorization_ref:str)->dict:
    job_id=uuid.uuid4().hex
    now=int(time.time())
    conn=_db()
    conn.execute(
        "INSERT INTO assessment_jobs(job_id,tenant_id,user_id,email,role,name,target,profile,authorization_ref,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (job_id,principal.tenant_id,principal.user_id,principal.email,principal.role,principal.name,target,profile,authorization_ref,"queued",now),
    )
    conn.commit(); conn.close()
    return get_job(job_id,principal.tenant_id)


def get_job(job_id:str,tenant_id:str)->dict|None:
    conn=_db()
    row=conn.execute("SELECT * FROM assessment_jobs WHERE job_id=? AND tenant_id=?",(job_id,tenant_id)).fetchone()
    conn.close()
    if not row: return None
    out=dict(row)
    if out.get("result_json"):
        out["result"]=json.loads(out.pop("result_json"))
    else:
        out.pop("result_json",None)
        out["result"]=None
    out["materialized"]=bool(out.get("materialized"))
    return out


def claim_next_job()->dict|None:
    conn=_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row=conn.execute("SELECT * FROM assessment_jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
        if not row:
            conn.commit()
            return None
        now=int(time.time())
        updated=conn.execute(
            "UPDATE assessment_jobs SET status='running',started_at=? WHERE job_id=? AND status='queued'",
            (now,row["job_id"]),
        ).rowcount
        conn.commit()
        if not updated:
            return None
        return dict(row)
    finally:
        conn.close()


def complete_job(job_id:str,result:dict)->None:
    conn=_db()
    conn.execute(
        "UPDATE assessment_jobs SET status='succeeded',result_json=?,completed_at=?,error=NULL WHERE job_id=?",
        (json.dumps(result,ensure_ascii=False,separators=(",",":")),int(time.time()),job_id),
    )
    conn.commit(); conn.close()


def fail_job(job_id:str,error:str)->None:
    conn=_db()
    conn.execute(
        "UPDATE assessment_jobs SET status='failed',completed_at=?,error=? WHERE job_id=?",
        (int(time.time()),str(error)[:4000],job_id),
    )
    conn.commit(); conn.close()


def mark_materialized(job_id:str,tenant_id:str)->None:
    conn=_db()
    conn.execute("UPDATE assessment_jobs SET materialized=1 WHERE job_id=? AND tenant_id=?",(job_id,tenant_id))
    conn.commit(); conn.close()
