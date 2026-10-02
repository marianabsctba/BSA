import json
import logging
import re
import time
import uuid

from .auth import _decode


logger=logging.getLogger("bsa.http")
if not logger.handlers:
    handler=logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate=False

_REQUEST_ID_RE=re.compile(r"^[A-Za-z0-9._:-]{8,128}$")


def request_id_from_header(value: str | None) -> str:
    candidate=str(value or "").strip()
    if candidate and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return uuid.uuid4().hex


def identity_from_request(request) -> tuple[str|None,str|None]:
    token=""
    auth=str(request.headers.get("Authorization") or "")
    if auth.lower().startswith("bearer "):
        token=auth.split(" ",1)[1].strip()
    elif request.cookies.get("bsa_session"):
        token=str(request.cookies.get("bsa_session") or "")
    if not token:
        return None,None
    try:
        claims=_decode(token)
    except Exception:
        return None,None
    return str(claims.get("tenant") or "") or None,str(claims.get("sub") or "") or None


def log_http_event(*,request_id: str,method: str,path: str,status_code: int,
                   duration_ms: float,tenant_id: str|None=None,user_id: str|None=None) -> dict:
    event={
        "event":"http_request",
        "request_id":request_id,
        "method":method,
        "path":path,
        "status_code":int(status_code),
        "duration_ms":round(float(duration_ms),2),
    }
    if tenant_id:
        event["tenant_id"]=tenant_id
    if user_id:
        event["user_id"]=user_id
    logger.info(json.dumps(event,ensure_ascii=False,separators=(",",":")))
    return event


def monotonic_ms() -> float:
    return time.monotonic()*1000
