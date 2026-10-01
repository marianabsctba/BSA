from dataclasses import dataclass
from typing import Iterable

@dataclass(frozen=True)
class CollectorPlan:
    collector: str
    target_kind: str
    target: str
    priority: int
    reason: str

COLLECTOR_CAPABILITIES={
    "dns":{"domain","hostname"},
    "certificate-transparency":{"domain"},
    "rdap":{"domain","hostname"},
    "ip_intel":{"ip"},
    "ports":{"ip","hostname"},
    "tls":{"hostname","ip"},
    "http":{"hostname","domain"},
}

def plan_collectors(pivots: Iterable[object], enabled: set[str] | None = None, max_jobs: int = 100) -> list[CollectorPlan]:
    enabled=enabled or set(COLLECTOR_CAPABILITIES)
    plans=[]
    seen=set()
    for p in pivots:
        kind=str(getattr(p,"kind",""))
        target=str(getattr(p,"value",""))
        conf=int(getattr(p,"confidence",0) or 0)
        if not target: continue
        for collector,caps in COLLECTOR_CAPABILITIES.items():
            if collector not in enabled or kind not in caps: continue
            key=(collector,kind,target)
            if key in seen: continue
            seen.add(key)
            priority=min(100,round(conf*0.7+30))
            plans.append(CollectorPlan(collector,kind,target,priority,f"pivot {kind} requires {collector}"))
    plans.sort(key=lambda x:(x.priority,x.collector,x.target),reverse=True)
    return plans[:max(0,max_jobs)]
