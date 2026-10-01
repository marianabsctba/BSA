import os
import sqlite3
import json
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone



def _history_db():
    path=os.getenv("BSA_HISTORY_DB", str(Path("/tmp") / "bsa_history.db"))
    conn=sqlite3.connect(path, timeout=15)
    conn.row_factory=sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS asset_observations(tenant_id TEXT NOT NULL,fingerprint TEXT NOT NULL,observed_at TEXT NOT NULL,confidence INTEGER NOT NULL,evidence_count INTEGER NOT NULL,sources_json TEXT NOT NULL,tags_json TEXT NOT NULL,evidence_refs_json TEXT NOT NULL DEFAULT '[]',PRIMARY KEY(tenant_id,fingerprint,observed_at))")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_obs_tenant_fp ON asset_observations(tenant_id,fingerprint,observed_at)")
    conn.execute("""CREATE TABLE IF NOT EXISTS discovery_runs(
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, observed_at TEXT NOT NULL,
        fingerprint TEXT NOT NULL, value TEXT NOT NULL, asset_type TEXT NOT NULL,
        confidence INTEGER NOT NULL, evidence_signature TEXT NOT NULL,
        PRIMARY KEY(tenant_id,run_id,fingerprint))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_runs_tenant_time ON discovery_runs(tenant_id,observed_at)")
    conn.execute("""CREATE TABLE IF NOT EXISTS ctem_items(
        tenant_id TEXT NOT NULL, item_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL,
        finding_id TEXT, state TEXT NOT NULL, priority INTEGER NOT NULL,
        action TEXT NOT NULL, title TEXT NOT NULL, drivers_json TEXT NOT NULL,
        evidence_refs_json TEXT NOT NULL, leverage_score INTEGER NOT NULL DEFAULT 0,
        paths_affected INTEGER NOT NULL DEFAULT 0, risk_reduction_percent INTEGER NOT NULL DEFAULT 0,
        path_coverage_percent INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, resolved_at TEXT, verified_at TEXT)""")
    ctem_cols={r["name"] for r in conn.execute("PRAGMA table_info(ctem_items)").fetchall()}
    for col,typ,default in [("leverage_score","INTEGER","0"),("paths_affected","INTEGER","0"),("risk_reduction_percent","INTEGER","0"),("path_coverage_percent","INTEGER","0")]:
        if col not in ctem_cols: conn.execute(f"ALTER TABLE ctem_items ADD COLUMN {col} {typ} NOT NULL DEFAULT {default}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctem_tenant_state ON ctem_items(tenant_id,state,priority)")
    conn.execute("""CREATE TABLE IF NOT EXISTS ctem_verifications(
        verification_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, item_id TEXT NOT NULL,
        result TEXT NOT NULL, evidence_refs_json TEXT NOT NULL, notes TEXT NOT NULL,
        verified_at TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ctem_verification_tenant_item ON ctem_verifications(tenant_id,item_id,verified_at)")
    conn.execute("CREATE TABLE IF NOT EXISTS lifecycle_snapshots(tenant_id TEXT NOT NULL,fingerprint TEXT NOT NULL,value TEXT NOT NULL,asset_type TEXT NOT NULL,observed_at TEXT NOT NULL,confidence INTEGER NOT NULL,evidence_count INTEGER NOT NULL,evidence_signature TEXT NOT NULL,sources_json TEXT NOT NULL,tags_json TEXT NOT NULL,PRIMARY KEY(tenant_id,fingerprint,observed_at))")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_lifecycle_tenant_fp ON lifecycle_snapshots(tenant_id,fingerprint,observed_at)")
    cols={r["name"] for r in conn.execute("PRAGMA table_info(asset_observations)").fetchall()}
    if "evidence_refs_json" not in cols:
        conn.execute("ALTER TABLE asset_observations ADD COLUMN evidence_refs_json TEXT NOT NULL DEFAULT '[]'")
    lifecycle_cols={r["name"] for r in conn.execute("PRAGMA table_info(lifecycle_snapshots)").fetchall()}
    if "evidence_refs_json" not in lifecycle_cols:
        conn.execute("ALTER TABLE lifecycle_snapshots ADD COLUMN evidence_refs_json TEXT NOT NULL DEFAULT '[]'")
    conn.commit()
    return conn

@dataclass(frozen=True)
class Observation:
    fingerprint: str
    observed_at: str
    confidence: int
    evidence_count: int
    sources: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


_HISTORY: dict[str, list[Observation]] = {}


def record_observations(assets, tenant_id: str = "tenant-demo") -> list[Observation]:
    now = datetime.now(timezone.utc).isoformat()
    observations = []
    for asset in assets:
        obs = Observation(
            asset.fingerprint,
            now,
            asset.confidence,
            asset.evidence_count,
            tuple(asset.sources),
            tuple(asset.tags),
            tuple(asset.evidence_refs),
        )
        previous = _HISTORY.setdefault(f"{tenant_id}:{asset.fingerprint}", [])
        if not previous or previous[-1] != obs:
            previous.append(obs)
        observations.append(obs)
    conn=_history_db()
    for obs in observations:
        conn.execute("INSERT OR IGNORE INTO asset_observations(tenant_id,fingerprint,observed_at,confidence,evidence_count,sources_json,tags_json,evidence_refs_json) VALUES(?,?,?,?,?,?,?,?)",(tenant_id,obs.fingerprint,obs.observed_at,obs.confidence,obs.evidence_count,json.dumps(obs.sources),json.dumps(obs.tags),json.dumps(obs.evidence_refs)))
    conn.commit()
    conn.close()
    return observations


def history_for(fingerprint: str, tenant_id: str = "tenant-demo") -> list[Observation]:
    conn=_history_db()
    rows=conn.execute("SELECT * FROM asset_observations WHERE tenant_id=? AND fingerprint=? ORDER BY observed_at",(tenant_id,fingerprint)).fetchall()
    conn.close()
    if rows:
        return [Observation(r["fingerprint"],r["observed_at"],r["confidence"],r["evidence_count"],tuple(json.loads(r["sources_json"])),tuple(json.loads(r["tags_json"])),tuple(json.loads(r["evidence_refs_json"] or "[]"))) for r in rows]
    return list(_HISTORY.get(f"{tenant_id}:{fingerprint}", []))


def change_summary(fingerprint: str, tenant_id: str = "tenant-demo") -> dict:
    history = history_for(fingerprint, tenant_id)
    if not history:
        return {"state": "new", "observations": 0, "changes": []}

    changes = []
    if len(history) > 1:
        previous, current = history[-2], history[-1]
        if previous.confidence != current.confidence:
            changes.append({
                "kind": "confidence_change",
                "delta": current.confidence - previous.confidence,
            })
        if previous.evidence_count != current.evidence_count:
            changes.append({
                "kind": "evidence_change",
                "delta": current.evidence_count - previous.evidence_count,
            })
        added_sources = sorted(set(current.sources) - set(previous.sources))
        removed_sources = sorted(set(previous.sources) - set(current.sources))
        if added_sources:
            changes.append({"kind": "source_added", "values": added_sources})
        if removed_sources:
            changes.append({"kind": "source_removed", "values": removed_sources})
        added_tags = sorted(set(current.tags) - set(previous.tags))
        removed_tags = sorted(set(previous.tags) - set(current.tags))
        if added_tags:
            changes.append({"kind": "tag_added", "values": added_tags})
        if removed_tags:
            changes.append({"kind": "tag_removed", "values": removed_tags})

    return {
        "state": "new" if len(history) == 1 else ("changed" if changes else "stable"),
        "observations": len(history),
        "confidence_delta": history[-1].confidence - history[0].confidence,
        "first_seen": history[0].observed_at,
        "last_seen": history[-1].observed_at,
        "changes": changes,
    }


def exposure_snapshot(assets, findings):
    from .exposure import exposure_breakdown, exposure_band
    total = sum(exposure_breakdown(a, findings).score for a in assets)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset_count": len(assets),
        "open_findings": sum(1 for f in findings if f.status == "open"),
        "aggregate_exposure": round(total / len(assets)) if assets else 0,
    }


@dataclass(frozen=True)
class LifecycleSnapshot:
    fingerprint: str
    value: str
    asset_type: str
    observed_at: str
    confidence: int
    evidence_count: int
    evidence_signature: str
    sources: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

_LIFECYCLE: dict[str, list[LifecycleSnapshot]] = {}

def _evidence_signature(evidence: list[dict]) -> str:
    from hashlib import sha256
    import json
    stable = sorted([
        {
            "kind": str(e.get("kind","")),
            "value": str(e.get("value","")),
            "subject": str(e.get("subject","")),
        } for e in evidence
    ], key=lambda x:(x["kind"],x["subject"],x["value"]))
    return sha256(json.dumps(stable,ensure_ascii=False,separators=(",",":")).encode()).hexdigest()[:20]

def record_lifecycle(assets, evidence: list[dict], tenant_id: str = "tenant-demo") -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    signature = _evidence_signature(evidence)
    out=[]
    for asset in assets:
        key=asset.fingerprint
        value=getattr(asset,"value",key)
        asset_type=getattr(asset,"asset_type","unknown")
        sources=tuple(getattr(asset,"sources",()))
        tags=tuple(getattr(asset,"tags",()))
        evidence_refs=tuple(getattr(asset,"evidence_refs",()))
        evidence_count=int(getattr(asset,"evidence_count",0) or 0)
        current=LifecycleSnapshot(key,value,asset_type,now,asset.confidence,evidence_count,signature,sources,tags,evidence_refs)
        conn=_history_db()
        conn.execute("INSERT OR IGNORE INTO lifecycle_snapshots(tenant_id,fingerprint,value,asset_type,observed_at,confidence,evidence_count,evidence_signature,sources_json,tags_json,evidence_refs_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(tenant_id,key,value,str(asset_type),now,asset.confidence,evidence_count,signature,json.dumps(sources),json.dumps(tags),json.dumps(evidence_refs)))
        conn.commit()
        conn.close()
        history=_LIFECYCLE.setdefault(f"{tenant_id}:{key}",[])
        previous=history[-1] if history else None
        if previous is None or previous.evidence_signature != current.evidence_signature or previous.confidence != current.confidence:
            history.append(current)
        changes=[]
        if previous:
            if previous.evidence_signature != current.evidence_signature:
                changes.append({"kind":"evidence_changed","from":previous.evidence_signature,"to":current.evidence_signature})
            if previous.confidence != current.confidence:
                changes.append({"kind":"confidence_changed","delta":current.confidence-previous.confidence})
            if set(current.sources)-set(previous.sources):
                changes.append({"kind":"source_added","values":sorted(set(current.sources)-set(previous.sources))})
            if set(current.tags)-set(previous.tags):
                changes.append({"kind":"tag_added","values":sorted(set(current.tags)-set(previous.tags))})
        out.append({
            "fingerprint":key,"value":value,"type":asset_type,
            "state":"new" if previous is None else ("changed" if changes else "stable"),
            "first_seen":history[0].observed_at if history else now,
            "last_seen":now,"observations":len(history),
            "confidence":asset.confidence,"evidence_count":evidence_count,
            "changes":changes,"sources":list(sources),"tags":list(tags),"evidence_refs":list(evidence_refs),
        })
    return out

def lifecycle_for(fingerprint: str, tenant_id: str = "tenant-demo") -> dict:
    history=_LIFECYCLE.get(f"{tenant_id}:{fingerprint}",[])
    if not history:
        return {"state":"unknown","observations":0,"timeline":[]}
    return {
        "state":"changed" if len(history)>1 else "new",
        "observations":len(history),
        "first_seen":history[0].observed_at,
        "last_seen":history[-1].observed_at,
        "timeline":[{
            "observed_at":x.observed_at,"confidence":x.confidence,
            "evidence_count":x.evidence_count,"evidence_signature":x.evidence_signature,
            "sources":list(x.sources),"tags":list(x.tags),"evidence_refs":list(x.evidence_refs)
        } for x in history]
    }

def record_discovery_run(assets, evidence: list[dict], tenant_id: str, run_id: str) -> dict:
    """Persist a complete observed surface and return an evidence-backed diff."""
    now = datetime.now(timezone.utc).isoformat()
    signature = _evidence_signature(evidence)
    conn = _history_db()
    previous = conn.execute(
        "SELECT fingerprint,value,asset_type,confidence,evidence_signature FROM discovery_runs "
        "WHERE tenant_id=? AND observed_at=(SELECT MAX(observed_at) FROM discovery_runs WHERE tenant_id=?)",
        (tenant_id, tenant_id),
    ).fetchall()
    previous_map = {r["fingerprint"]: dict(r) for r in previous}
    current_map = {a.fingerprint: a for a in assets if a.fingerprint}
    for asset in assets:
        conn.execute(
            "INSERT OR REPLACE INTO discovery_runs(tenant_id,run_id,observed_at,fingerprint,value,asset_type,confidence,evidence_signature) VALUES(?,?,?,?,?,?,?,?)",
            (tenant_id, run_id, now, asset.fingerprint, asset.value, str(asset.asset_type), asset.confidence, signature),
        )
    conn.commit()
    conn.close()
    added = sorted(set(current_map) - set(previous_map))
    removed = sorted(set(previous_map) - set(current_map))
    changed = []
    for fp in sorted(set(current_map) & set(previous_map)):
        asset = current_map[fp]
        old = previous_map[fp]
        reasons = []
        if old["value"] != asset.value or old["asset_type"] != str(asset.asset_type):
            reasons.append("identity_changed")
        if old["confidence"] != asset.confidence:
            reasons.append("confidence_changed")
        if old["evidence_signature"] != signature:
            reasons.append("evidence_changed")
        if reasons:
            changed.append({"fingerprint":fp,"value":asset.value,"reasons":reasons,"evidence_refs":list(getattr(asset,"evidence_refs",()))})
    return {
        "run_id": run_id, "observed_at": now, "previous_run_available": bool(previous),
        "summary": {"added":len(added),"removed":len(removed),"changed":len(changed),"total":len(current_map)},
        "added": [{"fingerprint":fp,"value":current_map[fp].value,"evidence_refs":list(getattr(current_map[fp],"evidence_refs",()))} for fp in added],
        "removed": [{"fingerprint":fp,"value":previous_map[fp]["value"]} for fp in removed],
        "changed": changed,
    }

def diff_risk_context(diff: dict, assets: list, findings: list) -> dict:
    """Attach deterministic exposure/risk deltas to a discovery diff."""
    from .exposure import exposure_breakdown, exposure_band
    from .risk_engine import assess_risk, prioritize_surface_change
    by_fp={getattr(a,"fingerprint",None):a for a in assets}
    by_id={getattr(a,"id",None):a for a in assets}
    result=dict(diff)
    added=[]; removed=[]; changed=[]
    for item in diff.get("added",[]):
        a=by_fp.get(item.get("fingerprint"))
        if a:
            e=exposure_breakdown(a,findings)
            af=[x for x in findings if getattr(x,"asset_id",None)==getattr(a,"id",None) and getattr(x,"status","open")=="open"]
            risks=[assess_risk(x,a) for x in af]
            added.append({**item,"exposure_score":e.score,"exposure_band":exposure_band(e.score),"risk_score":max((x.score for x in risks),default=0),"risk_band":max((x.band for x in risks),default="low",key=lambda b:{"low":0,"medium":1,"high":2,"critical":3}[b]),"rationale":e.rationale})
        else: added.append(item)
    for item in diff.get("removed",[]):
        removed.append({**item,"state":"removed_from_latest_observation"})
    for item in diff.get("changed",[]):
        a=by_fp.get(item.get("fingerprint"))
        if a:
            e=exposure_breakdown(a,findings)
            af=[x for x in findings if getattr(x,"asset_id",None)==getattr(a,"id",None) and getattr(x,"status","open")=="open"]
            risks=[assess_risk(x,a) for x in af]
            changed.append({**item,"exposure_score":e.score,"exposure_band":exposure_band(e.score),"risk_score":max((x.score for x in risks),default=0),"risk_band":max((x.band for x in risks),default="low",key=lambda b:{"low":0,"medium":1,"high":2,"critical":3}[b]),"rationale":e.rationale})
        else: changed.append(item)
    result["added"]=added; result["removed"]=removed; result["changed"]=changed
    result["risk_context"]={"new_exposure":sum(x.get("exposure_score",0) for x in added),
                            "changed_exposure":sum(x.get("exposure_score",0) for x in changed),
                            "new_risk":sum(x.get("risk_score",0) for x in added),
                            "changed_risk":sum(x.get("risk_score",0) for x in changed),
                            "removed_count":len(removed)}
    return result

def upsert_ctem_item(item: dict, tenant_id: str) -> dict:
    """Persist a CTEM work item without silently changing its workflow state."""
    import uuid
    now=datetime.now(timezone.utc).isoformat()
    item_id=str(item.get("item_id") or uuid.uuid4())
    conn=_history_db()
    row=conn.execute("SELECT * FROM ctem_items WHERE item_id=? AND tenant_id=?",(item_id,tenant_id)).fetchone()
    if row:
        state=row["state"]
        resolved_at=row["resolved_at"]
        verified_at=row["verified_at"]
    else:
        state="new"; resolved_at=None; verified_at=None
    conn.execute("""INSERT OR REPLACE INTO ctem_items
        (tenant_id,item_id,asset_id,finding_id,state,priority,action,title,drivers_json,evidence_refs_json,leverage_score,paths_affected,risk_reduction_percent,path_coverage_percent,created_at,updated_at,resolved_at,verified_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (tenant_id,item_id,str(item.get("asset_id","")),item.get("finding_id"),state,int(item.get("priority",0)),
         str(item.get("action","validate")),str(item.get("title","CTEM item")),
         json.dumps(item.get("drivers",[]),ensure_ascii=False),
         json.dumps(item.get("evidence_refs",[]),ensure_ascii=False),
         int(item.get("leverage_score",0) or 0),int(item.get("paths_affected",0) or 0),
         int(item.get("risk_reduction_percent",0) or 0),int(item.get("path_coverage_percent",0) or 0),
         row["created_at"] if row else now,now,resolved_at,verified_at))
    conn.commit()
    out=dict(item); out.update({"item_id":item_id,"tenant_id":tenant_id,"state":state,"created_at":row["created_at"] if row else now,"updated_at":now})
    conn.close()
    return out

def update_ctem_state(item_id: str, tenant_id: str, new_state: str) -> dict:
    allowed={"new","acknowledged","in_progress","resolved","verified"}
    transitions={"new":{"acknowledged"}, "acknowledged":{"in_progress","resolved"},
                 "in_progress":{"resolved"}, "resolved":{"verified"}, "verified":set()}
    if new_state not in allowed: raise ValueError("invalid CTEM state")
    conn=_history_db()
    row=conn.execute("SELECT * FROM ctem_items WHERE item_id=? AND tenant_id=?",(item_id,tenant_id)).fetchone()
    if not row: raise KeyError("CTEM item not found")
    if new_state not in transitions.get(row["state"],set()):
        raise ValueError("invalid CTEM state transition")
    now=datetime.now(timezone.utc).isoformat()
    resolved_at=now if new_state=="resolved" else row["resolved_at"]
    verified_at=now if new_state=="verified" else row["verified_at"]
    conn.execute("UPDATE ctem_items SET state=?,updated_at=?,resolved_at=?,verified_at=? WHERE item_id=? AND tenant_id=?",
                 (new_state,now,resolved_at,verified_at,item_id,tenant_id))
    conn.commit()
    result=dict(row); result.update({"state":new_state,"updated_at":now,"resolved_at":resolved_at,"verified_at":verified_at})
    conn.close()
    return result

def list_ctem_items(tenant_id: str, states: set[str] | None = None) -> list[dict]:
    conn=_history_db()
    rows=conn.execute("SELECT * FROM ctem_items WHERE tenant_id=? ORDER BY priority DESC,updated_at DESC",(tenant_id,)).fetchall()
    conn.close()
    result=[]
    for row in rows:
        if states and row["state"] not in states: continue
        x=dict(row)
        x["drivers"]=json.loads(x.pop("drivers_json") or "[]")
        x["evidence_refs"]=json.loads(x.pop("evidence_refs_json") or "[]")
        result.append(x)
    return result


def materialize_ctem_from_diff(diff: dict, assets, findings, tenant_id: str, attack_paths: list[dict] | None = None, remediation_leverage: dict[str, dict] | None = None) -> list[dict]:
    """Turn evidence-backed discovery deltas into tenant-scoped CTEM work items."""
    from .risk_engine import prioritize_surface_change, attack_path_ctem_context
    by_fp={getattr(a,"fingerprint",None):a for a in assets}
    created=[]
    for change in list(diff.get("added",[]))+list(diff.get("changed",[])):
        asset=by_fp.get(change.get("fingerprint"))
        if asset is None:
            continue
        priority=prioritize_surface_change(change,asset,findings)
        if priority.get("state") != "prioritized":
            continue
        item={
            "item_id": f"surface:{tenant_id}:{change.get('fingerprint')}",
            "asset_id": str(getattr(asset,"id",change.get("fingerprint",""))),
            "finding_id": None,
            "priority": int(priority.get("priority",0)),
            "action": str(priority.get("action","validate")),
            "title": "Surface change requiring CTEM attention",
            "drivers": list(priority.get("drivers",[])),
            "evidence_refs": list(change.get("evidence_refs",[])),
        }
        if attack_paths:
            item=attack_path_ctem_context(item,attack_paths)
        leverage=(remediation_leverage or {}).get(str(getattr(asset,"id",change.get("fingerprint",""))))
        if leverage:
            item.update({
                "leverage_score": int(leverage.get("leverage_score",0) or 0),
                "paths_affected": int(leverage.get("paths_affected",0) or 0),
                "risk_reduction_percent": int(leverage.get("reduction_percent",leverage.get("risk_reduction_percent",0)) or 0),
                "path_coverage_percent": int(leverage.get("path_coverage_percent",0) or 0),
            })
            if item["leverage_score"] >= 80:
                item["drivers"].append("alto potencial de redução de risco")
        item["action"]="immediate" if item["priority"]>=85 else "expedite" if item["priority"]>=70 else "plan" if item["priority"]>=45 else "monitor"
        created.append(upsert_ctem_item(item,tenant_id))
    return created

def ctem_leverage_summary(items: list[dict]) -> dict:
    """Summarize remediation leverage for an operational CTEM queue."""
    active=[x for x in items if x.get("state") not in {"verified"}]
    return {
        "active_items":len(active),
        "high_leverage_items":sum(1 for x in active if int(x.get("leverage_score",0) or 0)>=80),
        "paths_affected":sum(int(x.get("paths_affected",0) or 0) for x in active),
        "weighted_risk_reduction":round(sum(
            int(x.get("risk_reduction_percent",0) or 0)*max(1,int(x.get("paths_affected",0) or 0))
            for x in active
        ) / max(1,sum(max(1,int(x.get("paths_affected",0) or 0)) for x in active))),
    }


def ctem_remediation_evidence(item: dict, verification: dict | None = None) -> dict:
    """Build an auditable before/after remediation evidence record."""
    before={
        "state":item.get("state"),
        "priority":int(item.get("priority",0) or 0),
        "leverage_score":int(item.get("leverage_score",0) or 0),
        "paths_affected":int(item.get("paths_affected",0) or 0),
        "evidence_refs":list(item.get("evidence_refs",[]) or []),
    }
    verification=verification or {}
    after={
        "result":verification.get("result"),
        "state":verification.get("state"),
        "evidence_refs":list(verification.get("evidence_refs",[]) or []),
        "verified_at":verification.get("verified_at"),
    }
    return {"before":before,"after":after,"evidence_complete":bool(after["result"] and after["evidence_refs"])}


def ctem_remediation_coverage(items: list[dict]) -> dict:
    """Measure how much active CTEM work has concrete remediation leverage."""
    active=[x for x in items if x.get("state") not in {"verified"}]
    with_leverage=[x for x in active if int(x.get("leverage_score",0) or 0)>0]
    total_paths=sum(max(1,int(x.get("paths_affected",0) or 0)) for x in active)
    covered_paths=sum(max(1,int(x.get("paths_affected",0) or 0)) for x in with_leverage)
    return {
        "active_items":len(active),
        "items_with_remediation_leverage":len(with_leverage),
        "remediation_coverage_percent":round(100*len(with_leverage)/max(1,len(active))),
        "path_coverage_percent":round(100*covered_paths/max(1,total_paths)),
    }


def ctem_operational_summary(items: list[dict], as_of: datetime | None = None) -> dict:
    """Return deterministic CTEM aging/SLA indicators for active work."""
    now=as_of or datetime.now(timezone.utc)
    active=[x for x in items if x.get("state") not in {"verified"}]
    overdue=0
    oldest_age_hours=0
    for item in active:
        try:
            created=datetime.fromisoformat(str(item["created_at"]).replace("Z","+00:00"))
            age=max(0,(now-created).total_seconds()/3600)
        except (KeyError,ValueError,TypeError):
            age=0
        oldest_age_hours=max(oldest_age_hours,int(age))
        p=int(item.get("priority",0) or 0)
        threshold=24 if p>=85 else 48 if p>=70 else 168 if p>=45 else None
        if threshold is not None and age>threshold:
            overdue+=1
    return {**ctem_leverage_summary(items),
            "overdue_items":overdue,
            "oldest_active_age_hours":oldest_age_hours}


def ctem_claim_operation(tenant_id: str, operation_key: str, action: str, item_id: str) -> bool:
    """Atomically claim a CTEM operation key; False means it was already claimed."""
    conn=_history_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS ctem_operations(
        tenant_id TEXT NOT NULL, operation_key TEXT NOT NULL, action TEXT NOT NULL,
        item_id TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(tenant_id,operation_key))""")
    now=datetime.now(timezone.utc).isoformat()
    try:
        conn.execute(
            "INSERT INTO ctem_operations(tenant_id,operation_key,action,item_id,created_at) VALUES(?,?,?,?,?)",
            (tenant_id,operation_key,action,item_id,now))
        conn.commit()
        return True
    except Exception as exc:
        if "UNIQUE" in str(exc).upper() or "PRIMARY KEY" in str(exc).upper():
            conn.rollback()
            return False
        conn.rollback()
        raise
    finally:
        conn.close()


def ctem_action_idempotency_key(item_id: str, action: str, request_id: str | None) -> str:
    """Build a stable operation key for safe client retries."""
    import hashlib
    raw=f"{item_id}:{action}:{request_id or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def ctem_action_transition(item: dict, action: str) -> str:
    """Validate an operational action against the canonical CTEM state machine."""
    transitions={
        "new":{"acknowledge":"acknowledged"},
        "acknowledged":{"start_remediation":"in_progress"},
        "in_progress":{"submit_for_verification":"resolved"},
        "resolved":{"verify":"verified"},
        "verified":{"closed":"verified"},
    }
    state=item.get("state")
    target=transitions.get(state,{}).get(action)
    if not target:
        raise ValueError("invalid CTEM action for current state")
    return target


def ctem_next_action(item: dict) -> dict:
    """Derive an operationally safe next action from explicit CTEM state."""
    state=item.get("state")
    if state=="new":
        action="acknowledge"
    elif state=="acknowledged":
        action="start_remediation"
    elif state=="in_progress":
        action="submit_for_verification"
    elif state=="resolved":
        action="verify"
    elif state=="verified":
        action="closed"
    else:
        action="review"
    return {
        "action":action,
        "requires_evidence":action in {"submit_for_verification","verify"},
        "state":state,
    }


def ctem_queue_page(items: list[dict], *, page: int = 1, page_size: int = 50) -> dict:
    """Paginate the canonical CTEM queue with bounded server-side page size."""
    if page < 1:
        raise ValueError("page must be >= 1")
    if page_size < 1 or page_size > 100:
        raise ValueError("page_size must be between 1 and 100")
    ordered=ctem_queue_view(items)["ordered_items"]
    total=len(ordered)
    start=(page-1)*page_size
    end=start+page_size
    return {
        "page":page,
        "page_size":page_size,
        "total":total,
        "total_pages":(total+page_size-1)//page_size,
        "items":ordered[start:end],
    }


def ctem_queue_filter(items: list[dict], *, state: str | None = None,
                      bucket: str | None = None, min_leverage: int | None = None) -> list[dict]:
    """Filter CTEM work without changing the canonical queue ordering."""
    allowed={"new","acknowledged","in_progress","resolved","verified"}
    if state is not None and state not in allowed:
        raise ValueError("invalid CTEM state filter")
    def matches(item):
        if state is not None and item.get("state") != state:
            return False
        p=int(item.get("priority",0) or 0)
        b="critical" if p>=85 else "high" if p>=70 else "medium" if p>=45 else "low"
        if bucket is not None and bucket != b:
            return False
        if min_leverage is not None and int(item.get("leverage_score",0) or 0) < min_leverage:
            return False
        return True
    return [x for x in ctem_queue_view(items)["ordered_items"] if matches(x)]


def ctem_queue_view(items: list[dict]) -> dict:
    """Build a deterministic, tenant-scoped operational CTEM queue view."""
    active=[x for x in items if x.get("state") not in {"verified"}]
    def key(x):
        return (-int(x.get("priority",0) or 0), -int(x.get("leverage_score",0) or 0),
                str(x.get("created_at","")), str(x.get("item_id","")))
    ordered=sorted(active,key=key)
    buckets={"critical":[],"high":[],"medium":[],"low":[]}
    for item in ordered:
        p=int(item.get("priority",0) or 0)
        bucket="critical" if p>=85 else "high" if p>=70 else "medium" if p>=45 else "low"
        buckets[bucket].append(item)
    return {
        "total_active":len(ordered),
        "ordered_items":ordered,
        "buckets":{k:{"count":len(v),"items":v} for k,v in buckets.items()},
    }


def ctem_audit_outcome(item: dict, verifications: list[dict]) -> dict:
    """Summarize observed remediation outcome from explicit verification evidence."""
    passed=sum(1 for v in verifications if v.get("result")=="passed")
    failed=sum(1 for v in verifications if v.get("result")=="failed")
    latest=verifications[-1] if verifications else None
    return {
        "verification_count":len(verifications),
        "passed_count":passed,
        "failed_count":failed,
        "latest_result":latest.get("result") if latest else None,
        "verified":item.get("state")=="verified" and bool(latest and latest.get("result")=="passed"),
        "evidence_complete":all(bool(v.get("evidence_refs")) for v in verifications) if verifications else False,
    }


def ctem_audit_diff(before: dict, after: dict) -> dict:
    """Describe measurable CTEM changes without inventing remediation claims."""
    fields=("state","priority","leverage_score","paths_affected","risk_reduction_percent","path_coverage_percent")
    changes={}
    for field in fields:
        b=before.get(field)
        a=after.get(field)
        if b != a:
            changes[field]={"before":b,"after":a}
    before_refs=set(before.get("evidence_refs",[]) or [])
    after_refs=set(after.get("evidence_refs",[]) or [])
    return {
        "changed_fields":changes,
        "evidence_added":sorted(after_refs-before_refs),
        "evidence_removed":sorted(before_refs-after_refs),
        "state_changed":before.get("state") != after.get("state"),
        "risk_reduced":(
            isinstance(before.get("priority"),(int,float)) and
            isinstance(after.get("priority"),(int,float)) and
            after["priority"] < before["priority"]
        ),
    }


def ctem_audit_integrity(item: dict, verifications: list[dict]) -> dict:
    """Return stable integrity metadata for an audit timeline."""
    import hashlib, json
    timeline=ctem_audit_timeline(item,verifications)
    canonical=json.dumps(timeline,ensure_ascii=False,sort_keys=True,separators=(",",":"))
    return {
        "algorithm":"sha256",
        "hash":hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "event_count":len(timeline),
        "evidence_ref_count":sum(len(x.get("evidence_refs",[]) or []) for x in timeline),
    }


def ctem_verification_history(item_id: str, tenant_id: str) -> list[dict]:
    conn=_history_db()
    rows=conn.execute(
        "SELECT result,evidence_refs_json,notes,verified_at FROM ctem_verifications WHERE tenant_id=? AND item_id=? ORDER BY verified_at",
        (tenant_id,item_id),
    ).fetchall()
    conn.close()
    return [{"result":r["result"],"evidence_refs":json.loads(r["evidence_refs_json"] or "[]"),
             "notes":r["notes"],"verified_at":r["verified_at"]} for r in rows]


def ctem_audit_timeline(item: dict, verifications: list[dict]) -> list[dict]:
    """Return a chronological, evidence-linked CTEM audit timeline."""
    timeline=[{
        "event":"created",
        "timestamp":item.get("created_at"),
        "state":item.get("state"),
        "priority":int(item.get("priority",0) or 0),
        "evidence_refs":list(item.get("evidence_refs",[]) or []),
    }]
    for verification in sorted(verifications,key=lambda x:str(x.get("verified_at",""))):
        timeline.append({
            "event":"verification",
            "timestamp":verification.get("verified_at"),
            "result":verification.get("result"),
            "state":verification.get("state"),
            "evidence_refs":list(verification.get("evidence_refs",[]) or []),
            "notes":verification.get("notes",""),
        })
    return timeline


def verify_ctem_item(item_id: str, tenant_id: str, result: str, evidence_refs: list[str], notes: str = "") -> dict:
    """Close a CTEM item only with explicit verification evidence."""
    import uuid
    if result not in {"passed","failed"}:
        raise ValueError("verification result must be passed or failed")
    if not evidence_refs:
        raise ValueError("verification evidence is required")
    conn=_history_db()
    row=conn.execute("SELECT * FROM ctem_items WHERE item_id=? AND tenant_id=?",(item_id,tenant_id)).fetchone()
    if not row:
        conn.close()
        raise KeyError("CTEM item not found")
    if row["state"] not in {"resolved","in_progress"}:
        conn.close()
        raise ValueError("CTEM item must be resolved before verification")
    if row["state"] == "in_progress":
        prior_failed=conn.execute(
            "SELECT 1 FROM ctem_verifications WHERE tenant_id=? AND item_id=? AND result='failed' LIMIT 1",
            (tenant_id,item_id),
        ).fetchone()
        if not prior_failed:
            conn.close()
            raise ValueError("CTEM item must be resolved before verification")
    now=datetime.now(timezone.utc).isoformat()
    verification_id=str(uuid.uuid4())
    conn.execute("INSERT INTO ctem_verifications(verification_id,tenant_id,item_id,result,evidence_refs_json,notes,verified_at) VALUES(?,?,?,?,?,?,?)",
                 (verification_id,tenant_id,item_id,result,json.dumps(evidence_refs,ensure_ascii=False),notes,now))
    new_state="verified" if result=="passed" else "in_progress"
    conn.execute("UPDATE ctem_items SET state=?,updated_at=?,verified_at=? WHERE item_id=? AND tenant_id=?",
                 (new_state,now,now if result=="passed" else None,item_id,tenant_id))
    conn.commit()
    out=dict(row)
    out.update({"state":new_state,"verification_id":verification_id,"verification_result":result,
                "verification_evidence_refs":evidence_refs,"verified_at":now if result=="passed" else None})
    conn.close()
    return out
