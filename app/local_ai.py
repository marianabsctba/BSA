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


def analyze_infrastructure_cluster(indicator, links):
    system=("You are Be Safe ASM Local Infrastructure Intelligence analyst. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence. Do not infer ownership or maliciousness solely from shared infrastructure. "
            "Separate observed links, hypotheses and unknowns. Return JSON keys: summary, observed_links, hypotheses, unknowns, confidence, validation.")
    raw=ask(system,"Analyze infrastructure correlation. JSON only.\n"+json.dumps({"indicator":indicator,"links":links},ensure_ascii=False,separators=(",",":")))
    if not raw: return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"summary":raw,"observed_links":[],"hypotheses":[],"unknowns":["Unstructured response"],"confidence":0,"validation":[]}

def plan_discovery(target, discovery):
    system=("You are Be Safe ASM Local Discovery Planner. Respond in Brazilian Portuguese. "
            "Use ONLY supplied discovery evidence. Never invent assets, DNS records, technologies, vulnerabilities or ownership. "
            "Your job is to maximize defensive discovery coverage while minimizing unnecessary probes. "
            "Prioritize passive evidence first, then safe bounded checks already supported by BSA. "
            "Return JSON only with keys: summary, confirmed_assets, candidate_assets, high_value_targets, technology_hypotheses, evidence_gaps, next_checks, risk_signals, confidence. "
            "Every recommendation must explain which supplied evidence triggered it.")
    compact=json.dumps({"target":target,"discovery":discovery},ensure_ascii=False,separators=(",",":"))
    raw=ask(system,"Plan the next discovery steps from this evidence. JSON only.\n"+compact)
    if not raw:
        return None
    try:
        data=json.loads(raw)
        return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"summary":raw,"confirmed_assets":[],"candidate_assets":[],"high_value_targets":[],"technology_hypotheses":[],"evidence_gaps":["structured AI response unavailable"],"next_checks":[],"risk_signals":[],"confidence":0}

def judge_correlation(subject, observations):
    system=("You are Be Safe ASM Local Evidence Judge. Respond in Brazilian Portuguese. "
            "Use ONLY supplied observations. Never invent facts. Decide whether observations can safely be correlated into one identity. "
            "Be conservative: conflicts must lower confidence and may require human validation. "
            "Return JSON only with keys: decision, confidence, supporting_evidence, conflicting_evidence, rationale, validation_required.")
    raw=ask(system,"Judge whether these observations belong to the same identity. JSON only.\n"+json.dumps({"subject":subject,"observations":observations},ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"decision":"needs_review","confidence":0,"supporting_evidence":[],"conflicting_evidence":[],"rationale":raw,"validation_required":True}

def correlate_exposure(target, evidence):
    system=("You are Be Safe ASM Local Exposure Correlator. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence. Correlate DNS, IP, certificate, technology, cloud and HTTP observations. "
            "Never infer ownership or maliciousness from a shared provider alone. "
            "Separate confirmed relationships, hypotheses, conflicts and unknowns. "
            "Return JSON keys: confirmed_links, hypotheses, conflicts, unknowns, confidence, next_validation.")
    raw=ask(system,"Correlate this target's evidence. JSON only.\n"+json.dumps({"target":target,"evidence":evidence},ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"confirmed_links":[],"hypotheses":[],"conflicts":[],"unknowns":["Unstructured AI response"],"confidence":0,"next_validation":[]}

def prioritize_discovery(target, evidence, signals):
    system=("You are Be Safe ASM Local Discovery Prioritizer. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence and deterministic signals. Do not invent infrastructure. "
            "Rank next defensive discovery checks by expected information gain, evidence quality and safety. "
            "Return JSON keys: priorities, rationale, evidence_gaps, confidence. Each priority must cite its triggering evidence.")
    raw=ask(system,"Prioritize next discovery checks. JSON only.\n"+json.dumps({"target":target,"evidence":evidence,"signals":signals},ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:return {"priorities":[],"rationale":raw,"evidence_gaps":["unstructured AI response"],"confidence":0}

def analyze_api_surface(target, endpoints, technologies=None):
    system=("You are Be Safe ASM Local API Surface Intelligence. Respond in Brazilian Portuguese. "
            "Use ONLY supplied endpoint and technology evidence. Never claim an endpoint is vulnerable merely because it exists or lacks declared authentication. "
            "Distinguish OBSERVED, INFERENCE, UNKNOWN and VALIDATION. Identify high-value administrative/mutation surfaces, authentication inconsistencies, "
            "unexpected exposure signals and evidence gaps. Do not invent endpoints, parameters, vulnerabilities or ownership. "
            "Return JSON keys: summary, observed, risk_signals, high_value_endpoints, auth_gaps, unknowns, validation, confidence.")
    payload={"target":target,"endpoints":endpoints[:1000],"technologies":(technologies or [])[:100]}
    raw=ask(system,"Analyze this API surface. JSON only.\n"+json.dumps(payload,ensure_ascii=False,separators=(",",":")))
    if not raw:
        return None
    try:
        data=json.loads(raw)
        return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"summary":raw,"observed":[],"risk_signals":[],"high_value_endpoints":[],"auth_gaps":[],"unknowns":["Unstructured local AI response"],"validation":[],"confidence":0}


def prioritize_collection(target, evidence, deterministic_signals, candidate_checks):
    system=("You are Be Safe ASM Local Collection Prioritizer. Respond in Brazilian Portuguese. "
            "Use ONLY supplied evidence, deterministic signals and the listed candidate checks. "
            "Choose which already-supported checks should run next to maximize defensive information gain while minimizing unnecessary traffic. "
            "Never invent a check, endpoint, asset, vulnerability or relationship. Never recommend out-of-scope targets. "
            "Return JSON keys: priorities, rejected_checks, evidence_gaps, rationale, confidence. "
            "Each priority must include check, reason, triggering_evidence, expected_information_gain and safety.")
    payload={"target":target,"evidence":evidence[:500],"signals":deterministic_signals,"candidate_checks":candidate_checks}
    raw=ask(system,"Prioritize collection. JSON only.\n"+json.dumps(payload,ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"priorities":[],"rejected_checks":[],"evidence_gaps":["Unstructured local AI response"],"rationale":raw,"confidence":0}


def validate_asset_identity(assets, evidence):
    system=("You are Be Safe ASM Local Asset Identity Validator. Respond in Brazilian Portuguese. "
            "Use ONLY supplied correlated assets and evidence. Validate whether observations should remain one asset or be split. "
            "Never infer ownership from shared cloud/CDN/provider infrastructure. Conflicts must reduce confidence. "
            "Return JSON only with keys: confirmed_identities, split_candidates, conflicts, unknowns, confidence, validation.")
    raw=ask(system,"Validate asset identities. JSON only.\n"+json.dumps({"assets":assets[:200],"evidence":evidence[:500]},ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"confirmed_identities":[],"split_candidates":[],"conflicts":[],"unknowns":["Unstructured local AI response"],"confidence":0,"validation":[]}


def analyze_attack_paths(graph: dict) -> dict | None:
    system=("You are Be Safe ASM Local Attack Path Analyst. Respond in Brazilian Portuguese. "
            "Use ONLY the supplied graph paths, nodes, edges and deterministic scores. "
            "Do not create paths, vulnerabilities, ownership or exploitability not present in the graph. "
            "The deterministic graph score is authoritative. Identify contextual signals, choke points, evidence weaknesses, "
            "control gaps and validation steps. Return JSON keys: path_signals, choke_points, control_gaps, evidence_weaknesses, "
            "validation, unknowns, confidence.")
    paths=(graph or {}).get("risk_paths",[])[:50]
    nodes=(graph or {}).get("nodes",[])[:300]
    edges=(graph or {}).get("edges",[])[:500]
    raw=ask(system,"Analyze deterministic attack paths. JSON only.\n"+json.dumps({"paths":paths,"nodes":nodes,"edges":edges},ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"path_signals":[],"choke_points":[],"control_gaps":[],"evidence_weaknesses":[],"validation":[],"unknowns":["Unstructured local AI response"],"confidence":0}


def prioritize_surface_candidates(candidates: list[dict], evidence: list[dict]) -> dict | None:
    system=("You are Be Safe ASM Surface Discovery Prioritizer. Respond in Brazilian Portuguese. "
            "Use ONLY supplied candidates and evidence. Prioritize candidates classified interesting/protected/unknown. "
            "Never promote negative-known responses. Do not invent URLs, vulnerabilities or assets. "
            "Return JSON keys: priorities, discarded, rationale, unknowns, confidence.")
    payload={"candidates":candidates[:300],"evidence":evidence[-500:]}
    raw=ask(system,"Prioritize surface candidates for deeper defensive collection. JSON only.\n"+
            json.dumps(payload,ensure_ascii=False,separators=(",",":")))
    if not raw:return None
    try:
        data=json.loads(raw); return data if isinstance(data,dict) else None
    except json.JSONDecodeError:
        return {"priorities":[],"discarded":[],"rationale":"Unstructured AI response","unknowns":[],"confidence":0}

