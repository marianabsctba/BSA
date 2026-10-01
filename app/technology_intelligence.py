from dataclasses import dataclass
import re

@dataclass(frozen=True)
class TechnologyObservation:
    product: str
    version: str | None
    confidence: int
    source: str
    evidence: str
    version_confirmed: bool

# Deliberately conservative: product aliases are normalized, versions are never inferred.
ALIASES = {
    "nginx":"nginx","apache":"apache http server","microsoft-iis":"microsoft iis",
    "iis":"microsoft iis","openresty":"openresty","cloudflare":"cloudflare",
    "wordpress":"wordpress","drupal":"drupal","joomla":"joomla",
}

VERSION_PATTERNS = [
    (r"nginx[/ ](?P<v>\d+(?:\.\d+){1,3})","nginx"),
    (r"apache[/ ](?P<v>\d+(?:\.\d+){1,3})","apache http server"),
    (r"microsoft-iis[/ ](?P<v>\d+(?:\.\d+){1,3})","microsoft iis"),
    (r"openresty[/ ](?P<v>\d+(?:\.\d+){1,3})","openresty"),
]

def _version(value: str, product: str):
    text=str(value or "").lower()
    for pattern, canonical in VERSION_PATTERNS:
        m=re.search(pattern,text)
        if m and canonical==product:
            return m.group("v")
    return None

def extract_technologies(evidence: list[dict]) -> list[TechnologyObservation]:
    out={}
    for e in evidence:
        kind=str(e.get("kind","")); value=str(e.get("value","")).strip()
        if not value: continue
        candidate=None
        if kind.startswith("technology:") or kind=="http_header:server":
            raw=value.lower()
            for alias,canonical in ALIASES.items():
                if alias in raw:
                    candidate=canonical;break
        if kind=="page_title":
            title=value.lower()
            for alias,canonical in ALIASES.items():
                if alias in title:
                    candidate=canonical;break
        if not candidate: continue
        version=_version(value,candidate)
        key=(candidate,version or "")
        obs=TechnologyObservation(candidate,version,int(e.get("confidence",50)),str(e.get("source","unknown")),kind,version is not None)
        prev=out.get(key)
        if not prev or obs.confidence>prev.confidence: out[key]=obs
    return sorted(out.values(),key=lambda x:(x.product,x.version or ""))

def technology_match_quality(observation: TechnologyObservation) -> dict:
    if observation.version_confirmed:
        return {"state":"version_confirmed","confidence":observation.confidence,"matching_allowed":True}
    return {"state":"product_only","confidence":min(observation.confidence,70),"matching_allowed":False,
            "reason":"produto identificado, mas versão não foi observada explicitamente"}
