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

def assess_risk(finding: Finding, asset: Asset | None) -> RiskAssessment:
    cvss=(finding.cvss or 0)*10
    epss=(finding.epss or 0)*100
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
    score=min(100,round(likelihood*.45+impact*.40+confidence*.15))
    if finding.kev: drivers.append("KEV / exploração conhecida")
    if finding.exploit_available: drivers.append("exploit disponível")
    if finding.epss is not None: drivers.append(f"EPSS {finding.epss:.1%}")
    if finding.cvss is not None: drivers.append(f"CVSS {finding.cvss:.1f}")
    if criticality>=4: drivers.append("alta criticidade de negócio")
    if finding.false_positive_confidence>=60: controls=["validar falso positivo antes de remediação"]
    else: controls=[]
    band="critical" if score>=85 else "high" if score>=70 else "medium" if score>=45 else "low"
    return RiskAssessment(score,band,likelihood,impact,exposure,exploit,business,confidence,drivers,controls)
