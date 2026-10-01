from dataclasses import dataclass
import re
from .models import Asset, Finding

@dataclass(frozen=True)
class RiskAssessment:
    score: int
    band: str
    likelihood: int
    impact: int
    exposure: int
    exploitability: int
    business_criticality: int
    confidence: int
    drivers: list[str]
    controls: list[str]

def _cpe_tokens(cpe: str | None) -> tuple[str,...]:
    if not cpe: return ()
    return tuple(x.lower() for x in re.split(r"[:/]",cpe) if x)

def normalize_cpe(cpe: str | None) -> str | None:
    if not cpe: return None
    value=cpe.strip().lower()
    if value.startswith("cpe:2.3:"): return value
    if value.startswith("cpe:/"): return value
    return None

def cpe_product(cpe: str | None) -> tuple[str|None,str|None]:
    c=normalize_cpe(cpe)
    if not c: return None,None
    if c.startswith("cpe:2.3:"):
        p=c.split(":")
        return (p[3] if len(p)>3 else None),(p[4] if len(p)>4 and p[4]!="*" else None)
    p=c[5:].split(":")
    return (p[1] if len(p)>1 else None),(p[2] if len(p)>2 and p[2]!="*" else None)

def apply_attack_path_context(priority: dict, paths: list[object]) -> dict:
    """Increase CTEM urgency only when paths are backed by evidence."""
    result=dict(priority)
    valid=[p for p in paths if getattr(p,"evidence",None) or getattr(p,"edges",())]
    if not valid:
        return result
    best=max(valid,key=lambda p:getattr(p,"score",0))
    path_score=int(getattr(best,"score",0))
    path_conf=int(getattr(best,"confidence",0))
    result["attack_path_score"]=path_score
    result["attack_path_confidence"]=path_conf
    result["priority"]=min(100,round(result["priority"]*.75+path_score*.15+path_conf*.10))
    result["drivers"]=list(result.get("drivers",[]))+["caminho de exposição sustentado por evidências"]
    return result

def assess_ctem_priority(finding: Finding, asset: Asset | None) -> dict:
    """Return a deterministic CTEM priority breakdown using vulnerability intelligence and exposure context."""
    risk=assess_risk(finding,asset)
    exploitability=risk.exploitability
    exposure=risk.exposure
    business=risk.business_criticality
    confidence=risk.confidence
    priority=min(100,round(exploitability*0.35+exposure*0.25+business*0.25+confidence*0.15))
    action="immediate" if priority>=85 else "expedite" if priority>=70 else "plan" if priority>=45 else "monitor"
    return {
        "priority":priority,
        "action":action,
        "drivers":risk.drivers,
        "exploitability":exploitability,
        "exposure":exposure,
        "business_criticality":business,
        "confidence":confidence,
    }

def assess_risk(finding: Finding, asset: Asset | None) -> RiskAssessment:
    cvss=(finding.cvss or 0)*10
    epss=(finding.epss or 0)*100
    evidence_strength=min(100, max(0, finding.confidence))
    identity_bonus=10 if finding.cpe else 0
    vuln_bonus=15 if finding.vulnerability_id else 0
    exploit=min(100,round(max(cvss,epss*0.8)+(25 if finding.kev else 0)+(15 if finding.exploit_available else 0)))
    exposure=15
    drivers=[]
    if asset and "internet-facing" in asset.tags:
        exposure+=35; drivers.append("exposto à Internet")
    if asset and "remote-access" in asset.tags:
        exposure+=15; drivers.append("acesso remoto")
    if asset and "production" in asset.tags:
        exposure+=10; drivers.append("produção")
    exposure=min(100,exposure)
    criticality=asset.criticality if asset else 3
    business=round((criticality/5)*100)
    impact=round(business*.65+min(100,asset.confidence if asset else 70)*.15+(30 if asset and asset.type.value in {"application","service"} else 10))
    likelihood=round(exploit*.65+exposure*.35)
    confidence=min(finding.confidence,asset.confidence if asset else finding.confidence)
    intelligence=min(100, round(evidence_strength*.55 + identity_bonus + vuln_bonus))
    score=min(100,round(likelihood*.40+impact*.35+confidence*.10+intelligence*.15))
    if finding.kev: drivers.append("KEV / exploração conhecida")
    if finding.exploit_available: drivers.append("exploit disponível")
    if finding.epss is not None: drivers.append(f"EPSS {finding.epss:.1%}")
    if finding.cvss is not None: drivers.append(f"CVSS {finding.cvss:.1f}")
    if finding.cpe: drivers.append("identificação técnica/CPE disponível")
    if finding.vulnerability_id: drivers.append("vulnerability ID correlacionado")
    if criticality>=4: drivers.append("alta criticidade de negócio")
    if finding.false_positive_confidence>=60: controls=["validar falso positivo antes de remediação"]
    else: controls=[]
    band="critical" if score>=85 else "high" if score>=70 else "medium" if score>=45 else "low"
    return RiskAssessment(score,band,likelihood,impact,exposure,exploit,business,confidence,drivers,controls)

def prioritize_surface_change(change: dict, asset: Asset | None, findings: list[Finding]) -> dict:
    """Turn an evidence-backed surface change into a CTEM work item."""
    relevant=[f for f in findings if getattr(f,"asset_id",None)==getattr(asset,"id",None)
             and getattr(f,"status","open")=="open"]
    assessments=[assess_ctem_priority(f,asset) for f in relevant]
    best=max(assessments,key=lambda x:x["priority"],default=None)
    exposure=int(change.get("exposure_score",0) or 0)
    risk=int(change.get("risk_score",0) or 0)
    evidence_backed=bool(change.get("fingerprint")) and (
        bool(change.get("evidence_refs")) or bool(change.get("reasons"))
    )
    delta=max(risk, exposure)
    if best:
        delta=max(delta, int(best["priority"]))
    if not evidence_backed:
        return {
            "state":"insufficient_evidence",
            "priority":0,
            "action":"validate",
            "drivers":["mudança sem evidência suficiente para priorização"],
        }
    action="immediate" if delta>=85 else "expedite" if delta>=70 else "plan" if delta>=45 else "monitor"
    return {
        "state":"prioritized",
        "priority":min(100,delta),
        "action":action,
        "exposure_score":exposure,
        "risk_score":risk,
        "finding_priority":best["priority"] if best else 0,
        "drivers":(best["drivers"] if best else []) + list(change.get("rationale",[])),
    }
