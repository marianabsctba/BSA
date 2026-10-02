import importlib
from pathlib import Path

from fastapi.testclient import TestClient

import app.local_ai as local_ai
import app.ollama_proxy as proxy


def test_local_ai_disabled_in_production_without_proxy_token(monkeypatch):
    monkeypatch.setattr(local_ai,"ENVIRONMENT","production")
    monkeypatch.setattr(local_ai,"OLLAMA_PROXY_TOKEN","")
    monkeypatch.setenv("BSA_AI_ENABLED","1")
    assert local_ai.enabled() is False


def test_local_ai_sends_bearer_token_to_proxy(monkeypatch):
    monkeypatch.setattr(local_ai,"ENVIRONMENT","production")
    monkeypatch.setattr(local_ai,"OLLAMA_PROXY_TOKEN","t"*40)
    monkeypatch.setenv("BSA_AI_ENABLED","1")
    captured={}

    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self,*args): return False
        def read(self): return b'{"response":"ok"}'

    def fake_urlopen(req,timeout):
        captured["authorization"]=req.get_header("Authorization")
        captured["url"]=req.full_url
        return FakeResponse()

    monkeypatch.setattr(local_ai.urllib.request,"urlopen",fake_urlopen)
    result=local_ai.ask("system","user")
    assert result=="ok"
    assert captured["authorization"]=="Bearer "+"t"*40


def test_ollama_proxy_rejects_missing_token(monkeypatch):
    monkeypatch.setattr(proxy,"ENVIRONMENT","production")
    monkeypatch.setattr(proxy,"PROXY_TOKEN","p"*40)
    client=TestClient(proxy.app)
    response=client.post("/api/generate",json={"model":"qwen","prompt":"hello","stream":False})
    assert response.status_code==401


def test_production_compose_isolates_ollama_from_api():
    compose=Path("docker-compose.production.yml").read_text(encoding="utf-8")
    assert "networks: [bsa_ai_backend]" in compose
    assert "networks: [bsa_ai_backend, bsa_ai_client]" in compose
    assert "networks: [bsa_ai_client, bsa_app, bsa_egress]" in compose
    api_block=compose.split("  api:",1)[1].split("\n  worker:",1)[0]
    assert "http://ai-proxy:11435" in api_block
    assert "http://ollama:11434" not in api_block
    assert "BSA_OLLAMA_PROXY_TOKEN:" in api_block
