"""Digital Risk Protection / CTI layer for BSA.

Vendor-neutral primitives inspired by current DRP/EASM market patterns:
brand abuse, phishing, leaks, VIP exposure, dark web, supply chain and takedown.
"""
import os, sqlite3, json, time, uuid, hashlib
from pathlib import Path
from pydantic import BaseModel, Field
from .assessment_engine import mask_public_data

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
    return [mask_public_data(json.loads(r["payload"])) for r in rows]

def create_takedown(tenant_id,event_id,provider,reason,priority):
    tid=str(uuid.uuid4()); now=int(time.time())
    p={"takedown_id":tid,"event_id":event_id,"provider":provider or "auto-routing","reason":reason,
       "priority":priority,"status":"queued","attempts":0,"sla_hours":24,"timeline":[{"status":"queued","ts":now}]}
    c=_db(); c.execute("INSERT INTO takedowns VALUES(?,?,?,?,?,?)",(tid,tenant_id,event_id,json.dumps(p),now,now)); c.commit(); c.close(); return p

def list_takedowns(tenant_id):
    c=_db(); rows=c.execute("SELECT payload FROM takedowns WHERE tenant_id=? ORDER BY updated_at DESC",(tenant_id,)).fetchall(); c.close()
    return [json.loads(r["payload"]) for r in rows]


class BrandAnalysis(BaseModel):
    indicator: str
    brand: str
    title: str=""
    html_excerpt: str=""
    image_hash: str|None=None
    visual_similarity: int|None=None
    text_similarity: int|None=None

def _similarity(a,b):
    a=set(str(a).lower().split()); b=set(str(b).lower().split())
    return round(len(a&b)/max(1,len(a|b))*100)

def analyze_brand_impersonation(tenant_id, analysis: BrandAnalysis):
    visual=analysis.visual_similarity
    text=analysis.text_similarity if analysis.text_similarity is not None else _similarity(analysis.title,analysis.brand)
    score=round((visual*0.65 + text*0.35)) if visual is not None else text
    reasons=[]
    if visual is not None and visual>=75: reasons.append("high_visual_similarity")
    if text>=60: reasons.append("brand_text_similarity")
    if analysis.indicator.lower().find(analysis.brand.lower().replace(" ",""))>=0: reasons.append("brand_in_indicator")
    verdict="likely_impersonation" if score>=70 and len(reasons)>=1 else ("needs_review" if score>=45 else "low_signal")
    return {"indicator":analysis.indicator,"brand":analysis.brand,"score":score,"visual_similarity":visual,
            "text_similarity":text,"verdict":verdict,"reasons":reasons,
            "evidence":{"html_excerpt":analysis.html_excerpt,"image_hash":analysis.image_hash},
            "human_review_required":verdict!="likely_impersonation"}


class InfrastructureIndicator(BaseModel):
    indicator: str
    indicator_type: str="domain"
    ip: str|None=None
    asn: str|None=None
    registrar: str|None=None
    nameservers: list[str]=[]
    certificate_sha256: str|None=None
    favicon_sha256: str|None=None
    redirect_chain: list[str]=[]
    related_domains: list[str]=[]
    screenshot_hash: str|None=None
    source: str="manual"
    confidence: int=70

def infrastructure_fingerprint(item: InfrastructureIndicator) -> str:
    parts=[item.ip,item.asn,item.registrar,item.certificate_sha256,item.favicon_sha256,item.screenshot_hash,*item.nameservers,*item.related_domains,*item.redirect_chain]
    normalized="|".join(sorted(str(x).strip().lower() for x in parts if x))
    return hashlib.sha256(normalized.encode()).hexdigest()[:20] if normalized else ""

def build_infrastructure_links(item: InfrastructureIndicator):
    links=[]
    for value,kind in [(item.ip,"ip"),(item.asn,"asn"),(item.registrar,"registrar"),(item.certificate_sha256,"certificate"),(item.favicon_sha256,"favicon"),(item.screenshot_hash,"screenshot")]:
        if value: links.append({"type":kind,"value":value,"confidence":item.confidence})
    for ns in item.nameservers: links.append({"type":"nameserver","value":ns,"confidence":item.confidence})
    for domain in item.related_domains: links.append({"type":"related_domain","value":domain,"confidence":item.confidence})
    for target in item.redirect_chain: links.append({"type":"redirect","value":target,"confidence":item.confidence})
    return {"indicator":item.indicator,"indicator_type":item.indicator_type,"infrastructure_fingerprint":infrastructure_fingerprint(item),"links":links,"link_count":len(links),
            "cluster_strength":min(100, round(sum(x["confidence"] for x in links)/max(1,len(links)))),
            "evidence_required":not bool(links)}


def build_infrastructure_graph(item: InfrastructureIndicator):
    nodes=[{"id":"indicator:"+item.indicator,"type":item.indicator_type,"label":item.indicator,"confidence":item.confidence}]
    edges=[]
    seen=set()
    for link in build_infrastructure_links(item)["links"]:
        nid=link["type"]+":"+link["value"]
        if nid in seen: continue
        seen.add(nid)
        nodes.append({"id":nid,"type":link["type"],"label":link["value"],"confidence":link["confidence"]})
        edges.append({"source":"indicator:"+item.indicator,"target":nid,"type":link["type"],"confidence":link["confidence"],"evidence":"explicit_observation"})
    return {"nodes":nodes,"edges":edges,"summary":{"nodes":len(nodes),"edges":len(edges),"avg_edge_confidence":round(sum(e["confidence"] for e in edges)/len(edges)) if edges else 0}}
