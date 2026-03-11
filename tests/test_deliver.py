"""Tests for deliver.py fixes."""
import os
import sys
import importlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
