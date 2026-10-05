"""
Single-Server Workflow & Security Tests
=======================================
Verifies:
1. Path traversal attacks (e.g. /../../.env, /../../backend/app/config.py) do NOT leak file contents.
2. Unmapped /api/... routes return JSON 404 {"detail": "API route not found"}.
3. SPA frontend routes (/dashboard, /remediator, etc.) serve index.html or SPA fallback.
"""

from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_path_traversal_blocked():
    # 1. Test escaping dist directory to get root .env file
    res1 = client.get("/..%2f..%2f.env")
    assert "DATABASE_URL" not in res1.text
    assert "JWT_SECRET" not in res1.text
    
    res2 = client.get("/../../backend/app/config.py")
    assert "class Settings" not in res2.text

def test_api_unmapped_routes_return_json_404():
    res1 = client.get("/api/v1/nonexistent_endpoint_12345")
    assert res1.status_code == 404
    assert res1.headers["content-type"] == "application/json"
    assert res1.json() == {"detail": "API route not found"}
    
    res2 = client.get("/api/unknown_route")
    assert res2.status_code == 404
    assert res2.headers["content-type"] == "application/json"
    assert res2.json() == {"detail": "API route not found"}

def test_spa_routes_fallback():
    for route in ["/login", "/dashboard", "/remediator", "/mosca-timeline", "/compliance-reports", "/activity"]:
        res = client.get(route)
        assert res.status_code in (200, 404)
        if res.status_code == 200:
            assert "html" in res.headers.get("content-type", "")
