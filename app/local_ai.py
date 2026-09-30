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


def explain_attack_path(path, evidence):
    system=("You are Be Safe ASM Local Attack Path Analyst. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence. Never invent a relationship or security control. "
            "Separate FACTS, INFERENCE, UNKNOWN and RECOMMENDED VALIDATION. "
            "Return concise JSON with keys summary, facts, inference, unknowns, validation, confidence.")
    compact=json.dumps({"path":path,"evidence":evidence},ensure_ascii=False,separators=(",",":"))
    raw=ask(system, "Analyze this attack path and return JSON only.\n"+compact)
    if not raw:
        return None
    try:
        data=json.loads(raw)
        return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"summary":raw,"facts":[],"inference":[],"unknowns":["Structured local AI response was not valid JSON."],"validation":[],"confidence":0}


def analyze_brand_context(brand, indicator, evidence):
    system=("You are Be Safe ASM Local Brand Protection Analyst. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence. Do not claim visual similarity unless a numeric visual score is supplied. "
            "Separate observed facts from inference and always flag human review when evidence is insufficient. "
            "Return JSON keys: verdict, summary, facts, indicators, unknowns, confidence, recommended_action.")
    compact=json.dumps({"brand":brand,"indicator":indicator,"evidence":evidence},ensure_ascii=False,separators=(",",":"))
    raw=ask(system,"Analyze this possible brand impersonation. JSON only.\n"+compact)
    if not raw: return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"verdict":"needs_review","summary":raw,"facts":[],"indicators":[],"unknowns":["Unstructured AI response"],"confidence":0,"recommended_action":"human_review"}
