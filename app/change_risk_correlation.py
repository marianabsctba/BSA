from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class ChangeCorrelation:
    change_id: str
    asset_key: str
    technical_category: str
    impact: int
    risk_delta: int
    evidence_refs: tuple[str,...]
    drivers: tuple[str,...]

def correlate_change_with_risk(events: Iterable[object], risk_context: dict | None = None) -> list[ChangeCorrelation]:
    from .change_intelligence import change_risk_delta
    from .technical_change_intelligence import technical_change_impact
    ctx=risk_context or {}
    out=[]
    for idx,event in enumerate(events):
        tech=technical_change_impact(event,ctx)
        generic=change_risk_delta(event,ctx)
        risk_delta=max(-100,min(100,generic["delta"]+round(tech["impact"]*.35)))
        refs=tuple(getattr(event,"evidence_refs",()) or ())
        drivers=tuple(dict.fromkeys(generic["drivers"]+tech["drivers"]))
        out.append(ChangeCorrelation(f"chg-{idx+1}",str(getattr(event,"asset_key","")),tech["category"],tech["impact"],risk_delta,refs,drivers))
    return out

def aggregate_asset_change_risk(correlations: Iterable[ChangeCorrelation]) -> dict[str,int]:
    result={}
    for c in correlations:
        result[c.asset_key]=max(-100,min(100,result.get(c.asset_key,0)+c.risk_delta))
    return result
