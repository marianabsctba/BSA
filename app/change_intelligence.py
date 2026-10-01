from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class ChangeEvent:
    asset_key: str
    change_type: str
    before: str | None
    after: str | None
    evidence_refs: tuple[str,...]
    confidence: int
    severity: str = "info"
    metadata: dict = None

def _attrs(x):
    return {"kind":str(getattr(x,"kind","")),"value":str(getattr(x,"value","")),"confidence":int(getattr(x,"confidence",0) or 0),"evidence_ref":str(getattr(x,"evidence_ref","")),"source":str(getattr(x,"source",""))}

def compare_snapshots(before: Iterable[object], after: Iterable[object]) -> list[ChangeEvent]:
    def key(x): return (str(getattr(x,"kind","")),str(getattr(x,"value","")))
    b={key(x):x for x in before}; a={key(x):x for x in after}; events=[]
    for k,x in a.items():
        if k not in b:
            events.append(ChangeEvent(k[1],"added",None,k[1],(str(getattr(x,"evidence_ref","")),),int(getattr(x,"confidence",0) or 0),"info",{"kind":k[0]}))
        else:
            old=_attrs(b[k]); new=_attrs(x)
            if old["source"]!=new["source"] or old["confidence"]!=new["confidence"]:
                refs=tuple(r for r in (old["evidence_ref"],new["evidence_ref"]) if r)
                delta=new["confidence"]-old["confidence"]
                severity="warning" if abs(delta)>=15 else "info"
                events.append(ChangeEvent(k[1],"evidence_changed",old["evidence_ref"],new["evidence_ref"],refs,max(old["confidence"],new["confidence"]),severity,{"kind":k[0],"confidence_delta":delta}))
    for k,x in b.items():
        if k not in a:
            events.append(ChangeEvent(k[1],"removed",k[1],None,(str(getattr(x,"evidence_ref","")),),int(getattr(x,"confidence",0) or 0),"info",{"kind":k[0]}))
    return events

def classify_change(event: ChangeEvent, asset_context: dict | None = None) -> ChangeEvent:
    context=asset_context or {}
    severity=event.severity
    if event.change_type=="added" and context.get("internet_exposed"): severity="warning"
    if event.change_type=="removed" and context.get("critical"): severity="warning"
    return ChangeEvent(event.asset_key,event.change_type,event.before,event.after,event.evidence_refs,event.confidence,severity,event.metadata or {})

def summarize_changes(events: Iterable[ChangeEvent]) -> dict:
    events=list(events)
    by_type={}
    for e in events: by_type[e.change_type]=by_type.get(e.change_type,0)+1
    return {"total":len(events),"by_type":by_type,"warnings":sum(e.severity=="warning" for e in events)}
