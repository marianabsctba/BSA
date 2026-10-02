from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_takedown_routes_are_not_exposed():
    paths={route.path for route in app.routes if hasattr(route,"path")}
    assert "/api/v1/digital-risk/takedowns" not in paths
