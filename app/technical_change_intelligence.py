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

def compare_technical_snapshots(before: Iterable[object], after: Iterable[object]) -> list[TechnicalChange]:
    def attrs(x):
        return (str(getattr(x,"kind","")),str(getattr(x,"value","")),str(getattr(x,"evidence_ref","")),int(getattr(x,"confidence",0) or 0))
    b={attrs(x)[:2]:attrs(x) for x in before}
    a={attrs(x)[:2]:attrs(x) for x in after}
    events=[]
    for key,new in a.items():
        if key not in b:
            events.append(TechnicalChange(key[1],"added",None,key[1],(new[2],),new[3],"info"))
            continue
        old=b[key]
        if old[2]!=new[2] or old[3]!=new[3]:
            events.append(TechnicalChange(key[1],"evidence_changed",old[2],new[2],tuple(x for x in (old[2],new[2]) if x),max(old[3],new[3]),"warning" if abs(new[3]-old[3])>=15 else "info"))
    for key,old in b.items():
        if key not in a:
            events.append(TechnicalChange(key[1],"removed",key[1],None,(old[2],),old[3],"info"))
    return events

def classify_technical_change(event: TechnicalChange, context: dict | None = None) -> TechnicalChange:
    c=context or {}
    severity=event.severity
    if event.change_type=="added" and c.get("internet_exposed"): severity="warning"
    return TechnicalChange(event.asset_key,event.change_type,event.before,event.after,event.evidence_refs,event.confidence,severity)
