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

def compare_snapshots(before: Iterable[object], after: Iterable[object]) -> list[ChangeEvent]:
    def key(x):
        return (str(getattr(x,"kind","")),str(getattr(x,"value","")))
    b={key(x):x for x in before}
    a={key(x):x for x in after}
    events=[]
    for k,x in a.items():
        if k not in b:
            events.append(ChangeEvent(k[1],"added",None,k[1],(str(getattr(x,"evidence_ref","")),),int(getattr(x,"confidence",0) or 0),"info"))
    for k,x in b.items():
        if k not in a:
            events.append(ChangeEvent(k[1],"removed",k[1],None,(str(getattr(x,"evidence_ref","")),),int(getattr(x,"confidence",0) or 0),"info"))
    return events
