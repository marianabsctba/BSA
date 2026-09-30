"""Local AI gateway for BSA. Ollama-compatible, privacy-first and evidence-grounded."""
import json, os, urllib.request, urllib.error

OLLAMA_URL=os.getenv("BSA_OLLAMA_URL","http://127.0.0.1:11434")
OLLAMA_MODEL=os.getenv("BSA_OLLAMA_MODEL","qwen2.5:7b")
TIMEOUT=int(os.getenv("BSA_AI_TIMEOUT","12"))

def enabled():
    return os.getenv("BSA_AI_ENABLED","1").lower() in {"1","true","yes","on"}

def ask(system_prompt, user_prompt):
    if not enabled():
        return None
    payload=json.dumps({"model":OLLAMA_MODEL,"stream":False,"options":{"temperature":0.1},"system":system_prompt,"prompt":user_prompt}).encode()
    req=urllib.request.Request(OLLAMA_URL.rstrip("/")+"/api/generate",data=payload,headers={"Content-Type":"application/json"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=TIMEOUT) as resp:
            data=json.loads(resp.read().decode())
            return (data.get("response") or "").strip() or None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None

def analyze_exposure(question, evidence):
    system=("You are Be Safe ASM Local Exposure Intelligence. Answer in Brazilian Portuguese. "
            "Use ONLY the supplied evidence. Never invent assets, vulnerabilities, owners, controls or facts. "
            "If evidence is insufficient, say so. Be concise and operational. Cite asset IDs inline.")
    compact=json.dumps(evidence,ensure_ascii=False,separators=(",",":"))
    return ask(system, f"Question: {question}\nEvidence JSON: {compact}")
