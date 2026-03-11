"""Tests for deliver.py fixes."""
import os
import sys
import importlib
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_generate_tasks_from_findings_importable():
    """scheduler._generate_tasks_from_findings must be importable."""
    from scheduler import _generate_tasks_from_findings
    assert callable(_generate_tasks_from_findings)


def test_output_dir_respects_data_dir_env(tmp_path, monkeypatch):
    """OUTPUT_DIR must use DATA_DIR env var, not hardcoded path."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    if "deliver" in sys.modules:
        del sys.modules["deliver"]
    import deliver
    assert str(tmp_path) in str(deliver.OUTPUT_DIR), \
        f"OUTPUT_DIR should contain DATA_DIR path. Got: {deliver.OUTPUT_DIR}"
    assert deliver.OUTPUT_DIR == tmp_path / "client-deliverables"


def test_output_dir_defaults_to_cwd(monkeypatch):
    """Without DATA_DIR, OUTPUT_DIR defaults to ./client-deliverables."""
    monkeypatch.delenv("DATA_DIR", raising=False)
    if "deliver" in sys.modules:
        del sys.modules["deliver"]
    import deliver
    assert str(deliver.OUTPUT_DIR).endswith("client-deliverables")


def test_full_delivery_generates_tasks(tmp_path, monkeypatch):
    """full_delivery() must call _generate_onboard_tasks after scan."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    # Re-import deliver with the new DATA_DIR env before applying patches
    if "deliver" in sys.modules:
        del sys.modules["deliver"]
    import deliver
    deliver.OUTPUT_DIR = tmp_path / "client-deliverables"
    deliver.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    mock_scan = MagicMock(return_value={
        "domain": "test.com", "company_name": "Test Corp",
        "archer": {"findings": [
            {"title": "Missing DMARC", "severity": "HIGH", "category": "email_security",
             "description": "No DMARC record", "fix": "Add DMARC record"}
        ], "score": {"total": 45, "grade": "D", "label": "POOR", "breakdown": {}}},
        "score": 45, "grade": "D", "scan_date": "2026-01-01",
    })
    mock_questionnaire = MagicMock(return_value={
        "profile": {"gaps": [], "applicable_frameworks": [], "risk_score": 50,
                     "industry": "CPA", "employee_range": "11-25", "sensitive_data": []},
        "compliance": {},
    })
    mock_pdf = MagicMock(return_value=str(tmp_path / "report.pdf"))
    mock_proposal = MagicMock(return_value="Proposal text")
    mock_gen_tasks = MagicMock()

    with patch("deliver.run_scan", mock_scan), \
         patch("deliver.run_questionnaire", mock_questionnaire), \
         patch("deliver.generate_pdf_report", mock_pdf), \
         patch("deliver.generate_proposal", mock_proposal), \
         patch("deliver._generate_onboard_tasks", mock_gen_tasks):
        deliver.full_delivery("test.com", company_name="Test Corp", no_ai=True)

    mock_gen_tasks.assert_called_once()
