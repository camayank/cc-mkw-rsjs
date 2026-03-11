"""Tests for prompt key integrity — P57 and all agent prompt references."""
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prompt_library import PROMPTS


def test_p57_key_exists_in_prompt_library():
    assert "P57_COMPLIANCE_UPDATE" in PROMPTS


def test_p57_prompt_has_required_fields():
    p57 = PROMPTS["P57_COMPLIANCE_UPDATE"]
    assert "system" in p57, "P57 missing 'system' key"
    assert "stage" in p57, "P57 missing 'stage' key"


def test_p57_key_matches_agent_call():
    """The key used in agents_remaining.py must exist in PROMPTS."""
    agents_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "agents", "agents_remaining.py",
    )
    content = open(agents_file).read()
    # Find the call_prompt invocation in ComplyAgent
    match = re.search(r'call_prompt\(\s*["\'](\w+)["\']', content)
    assert match, "No call_prompt call found in agents_remaining.py"
    key = match.group(1)
    assert key in PROMPTS, f"Agent references '{key}' but it doesn't exist in PROMPTS"


def test_all_agent_prompt_keys_exist():
    """Every call_prompt("KEY"...) in agents/ must reference a valid PROMPTS key."""
    agents_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents"
    )
    pattern = re.compile(r'call_prompt\(\s*["\'](\w+)["\']')
    missing = []
    for fname in os.listdir(agents_dir):
        if not fname.endswith(".py"):
            continue
        content = open(os.path.join(agents_dir, fname)).read()
        for match in pattern.finditer(content):
            key = match.group(1)
            if key not in PROMPTS:
                missing.append(f"{fname}: {key}")
    assert not missing, f"Missing prompt keys: {missing}"
