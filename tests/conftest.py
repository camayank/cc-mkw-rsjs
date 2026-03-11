"""Shared fixtures for CyberComply test suite."""
import os
import sys
import json

import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def fresh_client_manager(tmp_path, monkeypatch):
    """Get a fresh client_manager with isolated CLIENTS_DIR."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET", "test-secret-key-for-testing")
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"
    client_manager.JWT_SECRET = "test-secret-key-for-testing"
    return client_manager


@pytest.fixture
def test_app(tmp_path, monkeypatch):
    """Import main app with patched DATA_DIR and mocked scheduler."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("JWT_SECRET", "test-secret-key-for-testing")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "testpass")

    # Mock scheduler before importing main
    from unittest.mock import MagicMock
    import scheduler
    monkeypatch.setattr(scheduler, "init_scheduler", lambda app=None: MagicMock())

    # Remove cached main module to pick up env changes
    for mod_name in list(sys.modules):
        if mod_name in ("main", "client_manager"):
            del sys.modules[mod_name]

    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"
    client_manager.JWT_SECRET = "test-secret-key-for-testing"

    import main
    main.DATA_DIR = tmp_path
    main.OUTPUT_DIR = tmp_path / "client-deliverables"
    main.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    return main.app


@pytest.fixture
def test_client(test_app):
    """TestClient wrapping the app."""
    from starlette.testclient import TestClient
    return TestClient(test_app, raise_server_exceptions=False)


@pytest.fixture
def authed_client(test_app, fresh_client_manager):
    """TestClient with pre-authenticated portal session for 'test_co'."""
    from starlette.testclient import TestClient

    cm = fresh_client_manager
    cm.create_client("test_co", "Test Corp", "test.com", industry="cpa")
    cm.set_portal_password("test_co", "Secure123!")
    token = cm.create_jwt("test_co")

    client = TestClient(test_app, raise_server_exceptions=False)
    client.cookies.set("portal_token", token)
    return client


@pytest.fixture
def sample_client_data():
    """Dict with all fields the portal expects."""
    return {
        "client_id": "test_co",
        "company_name": "Test Corp",
        "domain": "test.com",
        "industry": "cpa",
        "tier": "basic",
        "contact_name": "Jane Doe",
        "contact_email": "jane@test.com",
        "contact_title": "Partner",
        "advisor_name": "John Security",
        "next_call_date": "2025-02-15",
        "score_history": [
            {"score": 35, "grade": "D", "date": "2025-01-01"},
            {"score": 52, "grade": "C", "date": "2025-02-01"},
        ],
        "current_score": 52,
        "current_grade": "C",
        "frameworks": ["IRS 4557", "NIST CSF"],
        "tech_stack": ["Microsoft 365"],
        "created_at": "2025-01-01",
    }
