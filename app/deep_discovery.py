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
        value=value.strip()
        if kind in {"domain","hostname","reverse_dns"}:
            value=value.lower()
        elif kind=="asn":
            value=value.upper()
        if not value or not evidence_ref or not 0 <= confidence <= 100:
            continue
        if kind in {"ip","reverse_dns"} and kind=="ip" and not _valid_ip(value):
            continue
        if kind in {"domain","hostname"} and not _valid_ip(value):
            if len(value)>253 or " " in value or not re.fullmatch(r"[a-z0-9._:-]+",value):
                continue
        if kind=="reverse_dns":
            if len(value)>253 or " " in value or not re.fullmatch(r"[a-z0-9._:-]+",value):
                continue
        key=(kind,value)
        if key in seen: continue
        seen.add(key)
        out.append(DiscoveryPivot(kind,value,source,confidence,evidence_ref))
    return out

def derive_network_pivots(pivots: Iterable[DiscoveryPivot]) -> list[DiscoveryPivot]:
    """Normalize network pivots without performing network access."""
    rows=[]
    for p in pivots:
        if p.kind=="ip":
            rows.append(("reverse_dns",p.value,p.source,p.confidence,p.evidence_ref))
        elif p.kind=="asn":
            rows.append(("asn",p.value.upper(),p.source,p.confidence,p.evidence_ref))
        elif p.kind=="reverse_dns":
            rows.append(("hostname",p.value,p.source,p.confidence,p.evidence_ref))
    return build_discovery_pivots(rows)

def derive_certificate_pivots(pivots: Iterable[DiscoveryPivot], names: Iterable[str]) -> list[DiscoveryPivot]:
    rows=[]
    for p in pivots:
        if p.kind!="certificate":
            continue
        for name in names:
            rows.append(("hostname",name,p.source,p.confidence,p.evidence_ref))
    return build_discovery_pivots(rows)

def pivot_candidates(pivots: Iterable[DiscoveryPivot], allowed_kinds: set[str]) -> list[DiscoveryPivot]:
    return [p for p in pivots if p.kind in allowed_kinds]
