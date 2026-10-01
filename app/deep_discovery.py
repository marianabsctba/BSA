from dataclasses import dataclass, field
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
    parent_refs: tuple[str,...] = ()
    derivation: str = "observed"

@dataclass(frozen=True)
class DiscoveryCandidate:
    pivot: DiscoveryPivot
    score: int
    source_count: int
    source_diversity: int
    lineage_depth: int
    rationale: tuple[str,...] = ()

def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def _valid_name(value: str) -> bool:
    return len(value)<=253 and " " not in value and bool(re.fullmatch(r"[a-z0-9._:-]+",value))

def build_discovery_pivots(values: Iterable[tuple]) -> list[DiscoveryPivot]:
    out=[]
    seen=set()
    for row in values:
        if len(row)<5: continue
        kind,value,source,confidence,evidence_ref=row[:5]
        parent_refs=tuple(row[5]) if len(row)>5 and row[5] else ()
        derivation=str(row[6]) if len(row)>6 else "observed"
        value=str(value).strip()
        if kind in {"domain","hostname","reverse_dns"}: value=value.lower()
        elif kind=="asn": value=value.upper()
        if not value or not evidence_ref or not 0<=int(confidence)<=100: continue
        if kind=="ip" and not _valid_ip(value): continue
        if kind in {"domain","hostname","reverse_dns"} and not _valid_name(value): continue
        if kind=="asn" and not re.fullmatch(r"AS[0-9]+",value): continue
        key=(kind,value)
        if key in seen: continue
        seen.add(key)
        out.append(DiscoveryPivot(kind,value,str(source),int(confidence),str(evidence_ref),parent_refs,derivation))
    return out

def _derive(rows, kind, source, confidence, ref, parent, derivation):
    return [(kind,v,source,confidence,ref,parent,derivation) for v in rows if v]

def derive_network_pivots(pivots: Iterable[DiscoveryPivot]) -> list[DiscoveryPivot]:
    rows=[]
    for p in pivots:
        if p.kind=="ip":
            rows.append(("reverse_dns",p.value,p.source,p.confidence,p.evidence_ref,(p.evidence_ref,),"derived:ip-to-reverse-dns"))
        elif p.kind=="asn":
            rows.append(("asn",p.value.upper(),p.source,p.confidence,p.evidence_ref,(p.evidence_ref,),"observed:asn"))
        elif p.kind=="reverse_dns":
            rows.append(("hostname",p.value,p.source,p.confidence,p.evidence_ref,(p.evidence_ref,),"derived:reverse-dns-to-hostname"))
    return build_discovery_pivots(rows)

def derive_certificate_pivots(pivots: Iterable[DiscoveryPivot], names: Iterable[str]) -> list[DiscoveryPivot]:
    rows=[]
    for p in pivots:
        if p.kind=="certificate":
            for name in names:
                rows.append(("hostname",name,p.source,p.confidence,p.evidence_ref,(p.evidence_ref,),"derived:certificate-san"))
    return build_discovery_pivots(rows)

def pivot_candidates(pivots: Iterable[DiscoveryPivot], allowed_kinds: set[str]) -> list[DiscoveryPivot]:
    return [p for p in pivots if p.kind in allowed_kinds]

def rank_candidates(pivots: Iterable[DiscoveryPivot]) -> list[DiscoveryCandidate]:
    groups={}
    for p in pivots:
        key=(p.kind,p.value)
        groups.setdefault(key,[]).append(p)
    out=[]
    for key,items in groups.items():
        sources={p.source for p in items}
        conf=max(p.confidence for p in items)
        diversity=min(100,50+25*max(0,len(sources)-1))
        score=min(100,round(conf*0.55+diversity*0.25+max(0,100-10*max(0,len(items[0].parent_refs)))*0.20))
        depth=max((len(p.parent_refs) for p in items),default=0)
        rationale=["evidence-backed candidate",f"{len(sources)} source(s)",f"confidence={conf}"]
        if len(sources)>1: rationale.append("independent source corroboration")
        out.append(DiscoveryCandidate(max(items,key=lambda p:p.confidence),score,len(sources),diversity,depth,tuple(rationale)))
    return sorted(out,key=lambda x:(x.score,x.pivot.confidence,x.source_count),reverse=True)

def expand_discovery_chain(pivots: Iterable[DiscoveryPivot], max_rounds: int = 3, max_candidates: int = 500) -> list[DiscoveryPivot]:
    current=list(pivots)
    seen={(p.kind,p.value) for p in current}
    for _ in range(max(0,max_rounds)):
        derived=derive_network_pivots(current)
        fresh=[]
        for p in derived:
            key=(p.kind,p.value)
            if key not in seen:
                seen.add(key); fresh.append(p)
                if len(current)+len(fresh)>=max_candidates: break
        if not fresh: break
        current.extend(fresh)
    return current[:max_candidates]

def pivots_from_evidence(evidence: Iterable[object]) -> list[DiscoveryPivot]:
    rows=[]
    for item in evidence:
        kind=str(getattr(item,"kind","")); value=str(getattr(item,"value","")).strip()
        source=str(getattr(item,"source","")); confidence=int(getattr(item,"confidence",0) or 0)
        metadata=getattr(item,"metadata",{}) or {}
        ref=str(metadata.get("evidence_ref") or f"{source}:{kind}:{value}")
        if kind in {"a_record","aaaa_record"}: rows.append(("ip",value,source,confidence,ref))
        elif kind in {"alias","cname","certificate_name"}: rows.append(("hostname",value,source,confidence,ref))
        elif kind=="rdap_nameserver": rows.append(("hostname",value,source,confidence,ref))
        elif kind=="rdap_network": rows.append(("asn",value,source,confidence,ref))
    return build_discovery_pivots(rows)

def collect_discovery_pivots(target: str, collectors: Iterable[object], max_evidence: int = 2000) -> list[DiscoveryPivot]:
    evidence=[]
    for collector in collectors:
        collect=getattr(collector,"collect",None)
        if not callable(collect): continue
        try:
            evidence.extend(collect(target)[:max(0,max_evidence-len(evidence))])
        except Exception: continue
        if len(evidence)>=max_evidence: break
    return pivots_from_evidence(evidence)
