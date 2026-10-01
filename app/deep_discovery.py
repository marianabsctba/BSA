from dataclasses import dataclass
from typing import Iterable
import ipaddress
import re

@dataclass(frozen=True)
class DiscoveryPivot:
    kind: str
    value: str
    source: str
    confidence: int
    evidence_ref: str

def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def build_discovery_pivots(values: Iterable[tuple[str,str,str,int,str]]) -> list[DiscoveryPivot]:
    out=[]
    seen=set()
    for kind,value,source,confidence,evidence_ref in values:
        value=value.strip().lower()
        if not value or not evidence_ref or not 0 <= confidence <= 100:
            continue
        if kind in {"ip","reverse_dns"} and kind=="ip" and not _valid_ip(value):
            continue
        if kind in {"domain","hostname","reverse_dns"} and not _valid_ip(value):
            if len(value)>253 or " " in value or not re.fullmatch(r"[a-z0-9._:-]+",value):
                continue
        key=(kind,value)
        if key in seen: continue
        seen.add(key)
        out.append(DiscoveryPivot(kind,value,source,confidence,evidence_ref))
    return out

def pivot_candidates(pivots: Iterable[DiscoveryPivot], allowed_kinds: set[str]) -> list[DiscoveryPivot]:
    return [p for p in pivots if p.kind in allowed_kinds]
