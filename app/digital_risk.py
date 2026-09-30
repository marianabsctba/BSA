"""Digital Risk Protection / CTI layer for BSA.

Vendor-neutral primitives inspired by current DRP/EASM market patterns:
brand abuse, phishing, leaks, VIP exposure, dark web, supply chain and takedown.
"""
import os, sqlite3, json, time, uuid
from pathlib import Path
from pydantic import BaseModel, Field

DB_PATH=os.getenv("BSA_AUTH_DB",str(Path("/tmp")/"bsa_auth.db"))

class DigitalRiskEvent(BaseModel):
    category: str
    title: str
    indicator: str
    source: str="manual"
    severity: str="medium"
    confidence: int=70
    evidence: dict={}
    first_seen: str=""
    last_seen: str=""
    status: str="open"
    asset_id: str|None=None
    brand: str|None=None
    actor: str|None=None

class TakedownRequest(BaseModel):
    event_id: str
    provider: str|None=None
    reason: str="brand_abuse"
    priority: str="high"

def _db():
    c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS digital_risk(
      event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, payload TEXT NOT NULL,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS takedowns(
      takedown_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, event_id TEXT NOT NULL,
      payload TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)""")
    c.commit(); return c

def upsert_event(tenant_id,event):
    now=int(time.time()); eid=event.get("event_id") or str(uuid.uuid4())
    event={**event,"event_id":eid,"updated_at":now}
    c=_db(); c.execute("""INSERT INTO digital_risk(event_id,tenant_id,payload,created_at,updated_at)
      VALUES(?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at""",
      (eid,tenant_id,json.dumps(event,ensure_ascii=False),now,now)); c.commit(); c.close(); return event

def list_events(tenant_id,category=None):
    c=_db(); q="SELECT payload FROM digital_risk WHERE tenant_id=?"; args=[tenant_id]
    if category: q+=" AND json_extract(payload,'$.category')=?"; args.append(category)
    rows=c.execute(q+" ORDER BY updated_at DESC",args).fetchall(); c.close()
    return [json.loads(r["payload"]) for r in rows]

def create_takedown(tenant_id,event_id,provider,reason,priority):
    tid=str(uuid.uuid4()); now=int(time.time())
    p={"takedown_id":tid,"event_id":event_id,"provider":provider or "auto-routing","reason":reason,
       "priority":priority,"status":"queued","attempts":0,"sla_hours":24,"timeline":[{"status":"queued","ts":now}]}
    c=_db(); c.execute("INSERT INTO takedowns VALUES(?,?,?,?,?)",(tid,tenant_id,event_id,json.dumps(p),now,now)); c.commit(); c.close(); return p

def list_takedowns(tenant_id):
    c=_db(); rows=c.execute("SELECT payload FROM takedowns WHERE tenant_id=? ORDER BY updated_at DESC",(tenant_id,)).fetchall(); c.close()
    return [json.loads(r["payload"]) for r in rows]
