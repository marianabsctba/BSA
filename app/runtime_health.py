import os
import sqlite3
from pathlib import Path

from . import auth
from .job_queue import queue_health, worker_health, _db_path
from .store import _store_path


def _sqlite_readable(path: str | None) -> dict:
    if not path:
        return {"status":"disabled"}
    try:
        parent=Path(path).parent
        if not parent.exists():
            return {"status":"unavailable"}
        conn=sqlite3.connect(path,timeout=2)
        conn.execute("PRAGMA busy_timeout=2000")
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return {"status":"healthy"}
    except (OSError,sqlite3.Error):
        return {"status":"unavailable"}


def _asset_store_health() -> dict:
    backend=os.getenv("BSA_ASSET_REPOSITORY_BACKEND","legacy").strip().lower()
    if backend in {"legacy","sqlite","memory"}:
        state=_sqlite_readable(_store_path())
        return {**state,"backend":backend}
    if backend!="postgres":
        return {"status":"unavailable","backend":backend}
    dsn=os.getenv("BSA_DATABASE_URL","").strip()
    if not dsn:
        return {"status":"unavailable","backend":"postgres"}
    try:
        import psycopg
        with psycopg.connect(dsn,connect_timeout=2) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return {"status":"healthy","backend":"postgres"}
    except Exception:
        return {"status":"unavailable","backend":"postgres"}


def runtime_health() -> dict:
    auth_state=_sqlite_readable(auth.DB_PATH)
    store_state=_asset_store_health()
    queue_state=queue_health()
    workers=worker_health()

    production=os.getenv("BSA_ENV","development").lower() in {"production","prod"}
    required={
        "auth_db":auth_state["status"]=="healthy",
        "asset_store":store_state["status"]=="healthy" if production else store_state["status"] in {"healthy","disabled"},
        "queue":queue_state.get("status") not in {"unavailable","degraded"},
    }
    status="healthy" if all(required.values()) else "degraded"
    return {
        "status":status,
        "components":{
            "auth_db":auth_state,
            "asset_store":store_state,
            "queue":{
                "status":queue_state.get("status","unknown"),
                "queued":int(queue_state.get("queued",0)),
                "running":int(queue_state.get("running",0)),
            },
            "workers":{
                "status":workers.get("status","unknown"),
                "active_workers":int(workers.get("active_workers",0)),
            },
        },
    }
