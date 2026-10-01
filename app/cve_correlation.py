from dataclasses import dataclass
import re

@dataclass(frozen=True)
class CVERange:
    vulnerability_id: str
    vendor: str
    product: str
    version_start: str | None
    version_end: str | None
    exact_versions: tuple[str,...]=()
    source: str="catalog"

@dataclass(frozen=True)
class CVEMatch:
    vulnerability_id: str
    state: str
    confidence: int
    reason: str
    cpe: str | None
    observed_version: str | None
    source: str

def _parts(v):
    if v is None: return ()
    out=[]
    for x in re.split(r"[.+_-]",v.lower()):
        m=re.match(r"\d+",x)
        out.append(int(m.group()) if m else 0)
    return tuple(out)

def version_in_range(version: str, start: str|None, end: str|None) -> bool:
    v=_parts(version)
    return (not start or v>=_parts(start)) and (not end or v<=_parts(end))

def match_cve(observed_product: str, observed_version: str|None, cpe: str|None, candidates: list[CVERange]) -> list[CVEMatch]:
    out=[]
    seen=set()
    for c in candidates:
        if c.product.lower()!=observed_product.lower(): continue
        key=(c.vulnerability_id, c.product.lower(), observed_version or "")
        if key in seen: continue
        seen.add(key)
        if not observed_version:
            out.append(CVEMatch(c.vulnerability_id,"potential",65,"produto identificado, versão não confirmada; não afirmar vulnerabilidade afetada",cpe,None,c.source))
            continue
        affected=observed_version in c.exact_versions or version_in_range(observed_version,c.version_start,c.version_end)
        if affected:
            out.append(CVEMatch(c.vulnerability_id,"confirmed_affected",95,"versão observada dentro da faixa afetada",cpe,observed_version,c.source))
        else:
            out.append(CVEMatch(c.vulnerability_id,"not_affected",95,"versão observada fora da faixa afetada",cpe,observed_version,c.source))
    return out
