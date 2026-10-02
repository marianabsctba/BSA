from ...discovery import collect_target
from ...technology_intelligence import (
    extract_technologies,
    fingerprint_technology,
    technology_match_quality,
)


SUPPORTED_TECHNOLOGY_OPERATIONS={
    "technology.intelligence",
}


def supports(operation: str) -> bool:
    return operation in SUPPORTED_TECHNOLOGY_OPERATIONS


def run_technology_operation(operation: str, target: str, payload: dict, principal):
    if operation!="technology.intelligence":
        raise ValueError(f"unsupported technology operation: {operation}")

    data=collect_target(target,["http","tls"])
    observations=extract_technologies(data["evidence"])
    fingerprints=fingerprint_technology(data["evidence"])
    items=[]
    for observation in observations:
        item={
            "product":observation.product,
            "version":observation.version,
            "confidence":observation.confidence,
            "source":observation.source,
            "evidence":observation.evidence,
            "version_confirmed":observation.version_confirmed,
        }
        item["matching"]=technology_match_quality(observation)
        items.append(item)

    return {
        "target":data["target"],
        "technologies":items,
        "fingerprints":fingerprints,
        "summary":{
            "products":len(items),
            "version_confirmed":sum(item["version_confirmed"] for item in items),
            "product_only":sum(not item["version_confirmed"] for item in items),
            "fingerprint_candidates":len(fingerprints),
            "cve_matching":sum(item["matching"]["matching_allowed"] for item in items),
        },
    }
