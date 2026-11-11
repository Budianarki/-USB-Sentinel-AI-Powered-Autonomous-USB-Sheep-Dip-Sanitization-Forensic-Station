"""Tests for modular API routers and Web interface in USB Sentinel."""

import pytest
from fastapi.testclient import TestClient

from sentinel.ui.web import ui_app


@pytest.fixture
def client():
    return TestClient(ui_app)


def test_serve_dashboard(client: TestClient):
    """Verify root / serves the HTML dashboard."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "USB SENTINEL" in resp.text
    assert "claymorphism.css" in resp.text


def test_api_devices_endpoint(client: TestClient):
    """Verify /api/devices returns a valid device list."""
    resp = client.get("/api/devices")
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data
    assert "devices" in data
    assert isinstance(data["devices"], list)


def test_api_settings_ai_workflow(client: TestClient):
    """Verify /api/settings/ai get, update, and test endpoints."""
    # 1. Get settings
    get_res = client.get("/api/settings/ai")
    assert get_res.status_code == 200
    data = get_res.json()
    assert "active_provider" in data
    assert "providers" in data
    assert "gemini" in data["providers"]
    assert "mock" in data["providers"]

    # 2. Test provider connection (mock)
    test_res = client.post("/api/settings/ai/test", json={"provider": "mock"})
    assert test_res.status_code == 200
    test_data = test_res.json()
    assert test_data["success"] is True

    # 3. Update settings
    up_res = client.post(
        "/api/settings/ai",
        json={"provider": "mock", "model": "rule-based-mock", "save_to_env": False},
    )
    assert up_res.status_code == 200
    up_data = up_res.json()
    assert up_data["success"] is True
    assert up_data["active_provider"] == "mock"
