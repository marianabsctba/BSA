from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

@dataclass(frozen=True)
class CollectorPlan:
    collector: str
    target_kind: str
    target: str
    priority: int
    reason: str

@dataclass(frozen=True)
class CollectionCacheEntry:
    collector: str
    target_kind: str
    target: str
    collected_at: datetime
    ttl_seconds: int
    evidence_fingerprint: str

COLLECTOR_CAPABILITIES={
    "dns":{"domain","hostname"},
    "certificate-transparency":{"domain"},
    "rdap":{"domain","hostname"},
    "ip_intel":{"ip"},
    "ports":{"ip","hostname"},
    "tls":{"hostname","ip"},
    "http":{"hostname","domain"},
}

DEFAULT_TTL={
    "dns":3600,
    "certificate-transparency":21600,
    "rdap":86400,
    "ip_intel":86400,
    "ports":21600,
    "tls":21600,
    "http":3600,
}

def plan_collectors(pivots: Iterable[object], enabled: set[str] | None = None, max_jobs: int = 100, cache: Iterable[CollectionCacheEntry] = (), now: datetime | None = None) -> list[CollectorPlan]:
    enabled=enabled or set(COLLECTOR_CAPABILITIES)
    now=now or datetime.now(timezone.utc)
    fresh={(x.collector,x.target_kind,x.target) for x in cache if now <= x.collected_at+timedelta(seconds=max(0,x.ttl_seconds))}
    plans=[]; seen=set()
    for p in pivots:
        kind=str(getattr(p,"kind","")); target=str(getattr(p,"value","")); conf=int(getattr(p,"confidence",0) or 0)
        if not target: continue
        for collector,caps in COLLECTOR_CAPABILITIES.items():
            if collector not in enabled or kind not in caps: continue
            key=(collector,kind,target)
            if key in seen or key in fresh: continue
            seen.add(key)
            priority=min(100,round(conf*0.7+30))
            plans.append(CollectorPlan(collector,kind,target,priority,f"pivot {kind} requires {collector}"))
    plans.sort(key=lambda x:(x.priority,x.collector,x.target),reverse=True)
    return plans[:max(0,max_jobs)]

def is_cache_fresh(entry: CollectionCacheEntry, now: datetime | None = None) -> bool:
    now=now or datetime.now(timezone.utc)
    return now <= entry.collected_at+timedelta(seconds=max(0,entry.ttl_seconds))
