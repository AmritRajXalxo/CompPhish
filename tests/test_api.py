from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["name"] == "CompPhish API"


def test_health_endpoint_is_clear_when_model_missing_or_loaded():
    response = client.get("/health")
    assert response.status_code in (200, 503)
