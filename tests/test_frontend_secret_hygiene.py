from pathlib import Path
import re

FRONTEND = Path("frontend")
TEXT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".json", ".css", ".html"}

FORBIDDEN_PATTERNS = [
    re.compile(r"(?i)\bVITE_[A-Z0-9_]*(SECRET|TOKEN|API_KEY|APIKEY|PASSWORD|PRIVATE_KEY)\b"),
    re.compile(r"(?i)\b(client_secret|access_token|refresh_token|private_key|api_key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)authorization\s*[:=]\s*['\"]Bearer\s+[^'\"]+['\"]"),
]

def _frontend_text_files():
    for path in FRONTEND.rglob("*"):
        if not path.is_file():
            continue
        if "node_modules" in path.parts or "dist" in path.parts:
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            yield path

def test_frontend_contains_no_embedded_secrets():
    findings=[]
    for path in _frontend_text_files():
        text=path.read_text(encoding="utf-8",errors="ignore")
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.search(text):
                findings.append(f"{path}: {pattern.pattern}")
    assert not findings, "Frontend secret hygiene violation(s):\n" + "\n".join(findings)

def test_vite_sourcemaps_are_disabled():
    config=(FRONTEND/"vite.config.js").read_text(encoding="utf-8")
    assert re.search(r"sourcemap\s*:\s*false", config), "Production sourcemaps must remain disabled"
