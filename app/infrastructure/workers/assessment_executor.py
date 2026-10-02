from urllib.parse import urlparse

from ...dast import run_safe_web_assessment
from ...nuclei_engine import normalize_findings, run_nuclei


SUPPORTED_ASSESSMENT_OPERATIONS={
    "dast.safe_web",
    "dast.nuclei",
}


def supports(operation: str) -> bool:
    return operation in SUPPORTED_ASSESSMENT_OPERATIONS


def run_assessment_operation(operation: str, target: str, payload: dict, principal):
    payload=payload or {}

    if operation=="dast.safe_web":
        return run_safe_web_assessment(target)

    if operation=="dast.nuclei":
        profile=str(payload.get("profile") or "safe")
        if profile not in {"safe","standard"}:
            raise ValueError("unsupported DAST profile")
        scan=run_nuclei(target,profile=profile)
        scan["bsa_findings"]=normalize_findings(
            scan,
            asset_id=f"unresolved:{urlparse(target).hostname}",
        )
        return scan

    raise ValueError(f"unsupported assessment operation: {operation}")
