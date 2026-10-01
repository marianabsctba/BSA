from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class TechnicalChange:
    asset_key: str
    change_type: str
    before: str | None
    after: str | None
    evidence_refs: tuple[str,...]
    confidence: int
    severity: str = "info"
    category: str = "generic"

def _normalize(kind: str, value: str) -> tuple[str,str]:
    kind=kind.lower().strip(); value=value.strip()
    if kind in {"hostname","domain","certificate","technology"}:
        value=value.lower().rstrip(".")
    if kind in {"port","ports"}:
        value=value.lower().replace("tcp/","").replace("udp/","")
    return kind,value

def classify_technical_category(kind: str, value: str) -> str:
    k,v=_normalize(kind,value)
    if k in {"ip","a_record","aaaa_record"}: return "network"
    if k in {"port","ports","service"}: return "service"
    if k in {"certificate","certificate_name","tls"}: return "tls"
    if k in {"technology","http","http_tech","fingerprint"}: return "technology"
    if k in {"endpoint","route","api_endpoint"}: return "endpoint"
    if k in {"hostname","domain","dns","cname","alias"}: return "dns"
    return "generic"

def compare_technical_snapshots(before: Iterable[object], after: Iterable[object]) -> list[TechnicalChange]:
    def attrs(x):
        kind,value=_normalize(str(getattr(x,"kind","")),str(getattr(x,"value","")))
        return kind,value,str(getattr(x,"evidence_ref","")),int(getattr(x,"confidence",0) or 0)
    b={attrs(x)[:2]:attrs(x) for x in before}; a={attrs(x)[:2]:attrs(x) for x in after}; events=[]
    for key,new in a.items():
        category=classify_technical_category(*key)
        if key not in b:
            events.append(TechnicalChange(key[1],"added",None,key[1],(new[2],),new[3],"info",category)); continue
        old=b[key]
        if old[2]!=new[2] or old[3]!=new[3]:
            events.append(TechnicalChange(key[1],"evidence_changed",old[2],new[2],tuple(x for x in (old[2],new[2]) if x),max(old[3],new[3]),"warning" if abs(new[3]-old[3])>=15 else "info",category))
    for key,old in b.items():
        if key not in a:
            events.append(TechnicalChange(key[1],"removed",key[1],None,(old[2],),old[3],"info",classify_technical_category(*key)))
    return events

def classify_technical_change(event: TechnicalChange, context: dict | None = None) -> TechnicalChange:
    c=context or {}; severity=event.severity
    if event.change_type=="added" and c.get("internet_exposed"): severity="warning"
    return TechnicalChange(event.asset_key,event.change_type,event.before,event.after,event.evidence_refs,event.confidence,severity,event.category)

def technical_change_impact(event: TechnicalChange, context: dict | None = None) -> dict:
    c=context or {}; impact=0; drivers=[]
    if event.change_type=="added":
        impact=25; drivers.append("novo elemento técnico observado")
        if event.category=="service": impact+=20; drivers.append("novo serviço/porta")
        elif event.category=="tls": impact+=10; drivers.append("novo elemento TLS")
        elif event.category=="technology": impact+=15; drivers.append("nova tecnologia detectada")
        elif event.category=="endpoint": impact+=20; drivers.append("novo endpoint")
        elif event.category=="network": impact+=15; drivers.append("nova exposição de rede")
        elif event.category=="dns": impact+=10; drivers.append("nova evidência DNS")
    elif event.change_type=="removed":
        impact=-10; drivers.append("elemento técnico removido")
    elif event.change_type=="evidence_changed":
        impact=5 if event.confidence>=90 else 0
        if event.category=="tls": drivers.append("evidência TLS alterada")
        elif event.category=="technology": drivers.append("fingerprint tecnológico alterado")
        elif event.category=="dns": drivers.append("evidência DNS alterada")
    if c.get("internet_exposed") and event.change_type=="added":
        impact+=15; drivers.append("mudança em ativo exposto à Internet")
    return {"impact":max(-100,min(100,impact)),"drivers":drivers,"category":event.category}
