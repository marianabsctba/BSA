"""Authenticated, least-privilege proxy between BSA API and the local Ollama service."""
import hmac
import json
import os
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

ENVIRONMENT=os.getenv("BSA_ENV","development").lower()
PROXY_TOKEN=os.getenv("BSA_OLLAMA_PROXY_TOKEN","")
UPSTREAM_URL=os.getenv("BSA_OLLAMA_UPSTREAM_URL","http://ollama:11434").rstrip("/")
MAX_BODY_BYTES=int(os.getenv("BSA_OLLAMA_PROXY_MAX_BODY","1048576"))
TIMEOUT=int(os.getenv("BSA_OLLAMA_PROXY_TIMEOUT","30"))

app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)

_ALLOWED_KEYS={"model","prompt","system","stream","options","format"}


def _require_config():
    if ENVIRONMENT in {"production","prod"} and len(PROXY_TOKEN)<32:
        raise RuntimeError("BSA_OLLAMA_PROXY_TOKEN must be at least 32 characters in production")


def _authorized(request: Request) -> bool:
    header=request.headers.get("Authorization","")
    if not header.startswith("Bearer "):
        return False
    supplied=header[7:]
    return bool(PROXY_TOKEN) and hmac.compare_digest(supplied,PROXY_TOKEN)


@app.get("/health")
def health():
    _require_config()
    return {"status":"ok"}


@app.post("/api/generate")
async def generate(request: Request):
    _require_config()
    if not _authorized(request):
        raise HTTPException(status_code=401,detail="unauthorized")

    raw=await request.body()
    if len(raw)>MAX_BODY_BYTES:
        raise HTTPException(status_code=413,detail="request too large")
    try:
        payload=json.loads(raw.decode())
    except (UnicodeDecodeError,json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400,detail="invalid JSON") from exc
    if not isinstance(payload,dict):
        raise HTTPException(status_code=400,detail="JSON object required")

    unexpected=set(payload)-_ALLOWED_KEYS
    if unexpected:
        raise HTTPException(status_code=400,detail="unsupported Ollama fields")
    if payload.get("stream") not in {False,None}:
        raise HTTPException(status_code=400,detail="streaming is disabled")
    if not isinstance(payload.get("model"),str) or not isinstance(payload.get("prompt"),str):
        raise HTTPException(status_code=400,detail="model and prompt are required")

    forwarded=dict(payload)
    forwarded["stream"]=False
    data=json.dumps(forwarded,separators=(",",":")).encode()
    upstream=urllib.request.Request(
        UPSTREAM_URL+"/api/generate",
        data=data,
        headers={"Content-Type":"application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(upstream,timeout=TIMEOUT) as response:
            body=response.read(MAX_BODY_BYTES+1)
            if len(body)>MAX_BODY_BYTES:
                raise HTTPException(status_code=502,detail="upstream response too large")
            parsed=json.loads(body.decode())
    except HTTPException:
        raise
    except (urllib.error.URLError,TimeoutError,OSError,ValueError,json.JSONDecodeError) as exc:
        raise HTTPException(status_code=502,detail="local AI upstream unavailable") from exc

    if not isinstance(parsed,dict):
        raise HTTPException(status_code=502,detail="invalid upstream response")
    return JSONResponse(parsed)
