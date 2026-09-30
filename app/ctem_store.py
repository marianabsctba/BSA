"""Persistent CTEM plan storage for BSA."""
import os, sqlite3, time, json
from pathlib import Path

DB_PATH = os.getenv("BSA_AUTH_DB", str(Path("/tmp") / "bsa_auth.db"))

def _db():
    conn=sqlite3.connect(DB_PATH)
    conn.row_factory=sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS ctem_plans(
        plan_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, payload TEXT NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ctem_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
        status TEXT NOT NULL, risk_reduction INTEGER DEFAULT 0, residual_score INTEGER DEFAULT 0,
        ts INTEGER NOT NULL)""")
    conn.commit()
    return conn

def list_plans(tenant_id):
    conn=_db(); rows=conn.execute("SELECT payload FROM ctem_plans WHERE tenant_id=? ORDER BY updated_at DESC",(tenant_id,)).fetchall(); conn.close()
    return [json.loads(r["payload"]) for r in rows]

def get_plan(tenant_id, plan_id):
    conn=_db(); row=conn.execute("SELECT payload FROM ctem_plans WHERE tenant_id=? AND plan_id=?",(tenant_id,plan_id)).fetchone(); conn.close()
    return json.loads(row["payload"]) if row else None

def upsert_plan(tenant_id, plan):
    now=int(time.time()); conn=_db()
    conn.execute("""INSERT INTO ctem_plans(plan_id,tenant_id,payload,created_at,updated_at)
                    VALUES(?,?,?,?,?)
                    ON CONFLICT(plan_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
                 (plan["plan_id"],tenant_id,json.dumps(plan,separators=(",",":")),now,now))
    conn.execute("INSERT INTO ctem_history(plan_id,tenant_id,status,risk_reduction,residual_score,ts) VALUES(?,?,?,?,?,?)",
                 (plan["plan_id"],tenant_id,plan.get("status","planned"),int(plan.get("risk_reduction",0)),int(plan.get("residual_score",0)),now))
    conn.commit(); conn.close(); return plan


def history(tenant_id, days=90):
    cutoff=int(time.time())-days*86400
    conn=_db()
    rows=conn.execute("""SELECT status,risk_reduction,residual_score,ts FROM ctem_history
                         WHERE tenant_id=? AND ts>=? ORDER BY ts ASC""",(tenant_id,cutoff)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
