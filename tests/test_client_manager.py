"""Tests for client_manager additions."""
import os
import sys
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fresh_client_manager(tmp_path, monkeypatch):
    """Helper to get a fresh client_manager with isolated CLIENTS_DIR."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "client_manager" in sys.modules:
        del sys.modules["client_manager"]
    import client_manager
    client_manager.CLIENTS_DIR = tmp_path / "clients"
    return client_manager


def test_update_field(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    assert cm.update_field("test_com", "tech_stack", ["Microsoft 365"]) is True
    assert cm.get_client("test_com")["tech_stack"] == ["Microsoft 365"]


def test_update_field_nonexistent(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    assert cm.update_field("nonexistent", "tech_stack", []) is False


def test_find_by_domain(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    result = cm.find_by_domain("test.com")
    assert result is not None
    assert result["company_name"] == "Test Corp"


def test_find_by_domain_not_found(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    assert cm.find_by_domain("nonexistent.com") is None


def test_save_and_get_call_notes(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    cm.save_call_notes("test_com", "Discussed DMARC fix timeline.")
    result = cm.get_latest_call_notes("test_com")
    assert "Discussed DMARC fix timeline" in result


def test_get_call_notes_first_month(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    result = cm.get_latest_call_notes("test_com")
    assert "First month" in result


def test_log_communication(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    cm.log_communication("test_com", "welcome_email", "Welcome to CyberComply", "john@test.com")
    log_file = tmp_path / "clients" / "test_com" / "communications" / "log.jsonl"
    assert log_file.exists()
    entry = json.loads(log_file.read_text().strip())
    assert entry["type"] == "welcome_email"
    assert entry["recipient"] == "john@test.com"


def test_add_task_with_verifiable(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    task = cm.add_task("test_com", "Adopt WISP", "HIGH", "Compliance",
                        "Sign and distribute", "Review document", verifiable="manual")
    assert task["verifiable"] == "manual"
    task2 = cm.add_task("test_com", "Fix DMARC", "CRITICAL", "Email",
                         "Add DMARC record", "Add DNS record")
    assert task2["verifiable"] == "auto"


def test_magic_link_auto_refresh(tmp_path, monkeypatch):
    cm = _fresh_client_manager(tmp_path, monkeypatch)
    cm.create_client("test_com", "Test Corp", "test.com")
    token = cm.generate_magic_link("test_com")
    # Set expiry close to now (within 2 days)
    cm.update_field("test_com", "magic_token_expires",
                    (datetime.utcnow() + timedelta(days=1)).isoformat())
    # Verify should succeed AND extend
    assert cm.verify_magic_token("test_com", token) is True
    profile_after = cm.get_client("test_com")
    new_expires = datetime.fromisoformat(profile_after["magic_token_expires"])
    assert (new_expires - datetime.utcnow()).days >= 5
