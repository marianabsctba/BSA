from pathlib import Path
import json

def test_frontend_has_no_floating_latest_dependencies():
    data=json.loads(Path("frontend/package.json").read_text())
    deps={**data.get("dependencies",{}),**data.get("devDependencies",{})}
    assert deps
    assert all(v!="latest" for v in deps.values())

def test_vite_disables_source_maps():
    text=Path("frontend/vite.config.js").read_text()
    assert "sourcemap: false" in text
