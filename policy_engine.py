"""
CyberComply — Policy Document Engine
Generates actual policy documents via Claude API (not prompts-to-paste).
Uses POLICY_SYSTEM, POLICY_USER templates and POLICIES dict from prompt_library.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from datetime import date

from prompt_library import POLICIES, POLICY_SYSTEM, POLICY_USER
from prompt_engine import _get_client, _log_cost, _cache_key, _cache_get, _cache_set, MODEL, get_industry_context

logger = logging.getLogger("policy_engine")

# ─── Core 9 policies (default --policies set) ────────────
CORE_POLICIES = [
    "P29_WISP", "P30_IRP", "P31_AUP", "P32_ENCRYPTION", "P33_REMOTE_WORK",
    "P34_VENDOR_MGMT", "P35_DATA_CLASS", "P38_PASSWORD", "P40_TRAINING",
]

# ─── Finding-to-policy relevance map ─────────────────────
# Maps finding keywords → which policies they make relevant
POLICY_FINDING_MAP = {
    "P29_WISP":       ["security", "vulnerability", "risk", "compliance", "policy"],
    "P30_IRP":        ["breach", "incident", "compromise", "ransomware", "phishing", "malware", "bec"],
    "P31_AUP":        ["email", "web", "shadow it", "unauthorized", "personal"],
    "P32_ENCRYPTION": ["encryption", "ssl", "tls", "certificate", "plaintext", "unencrypted", "http"],
    "P33_REMOTE_WORK":["vpn", "remote", "rdp", "home", "wifi", "wireless"],
    "P34_VENDOR_MGMT":["vendor", "third-party", "third party", "saas", "cloud", "supplier"],
    "P35_DATA_CLASS": ["data", "pii", "sensitive", "classification", "retention", "ssn", "phi"],
    "P36_CHANGE_MGMT":["patch", "update", "outdated", "version", "change", "upgrade"],
    "P37_BCP":        ["backup", "disaster", "recovery", "continuity", "availability", "downtime"],
    "P38_PASSWORD":   ["password", "mfa", "authentication", "credential", "brute", "login", "2fa"],
    "P39_PHYSICAL":   ["physical", "office", "visitor", "clean desk", "server room", "disposal"],
    "P40_TRAINING":   ["training", "awareness", "phishing", "social engineering", "human"],
    "P41_MDM":        ["mobile", "byod", "device", "mdm", "smartphone", "tablet"],
    "P42_CLOUD":      ["cloud", "aws", "azure", "gcp", "saas", "iaas", "o365", "microsoft 365"],
    "P43_RETENTION":  ["retention", "destruction", "disposal", "archive", "gdpr", "ccpa"],
    "P44_SOCIAL_MEDIA":["social media", "linkedin", "twitter", "facebook", "communications"],
    "P45_CUSTOM":     [],
}


def _get_relevant_findings(findings: list, policy_key: str) -> str:
    """Filter findings relevant to a specific policy using keyword matching."""
    keywords = POLICY_FINDING_MAP.get(policy_key, [])
    if not keywords:
        # WISP gets all findings; unknown policies get top 5
        if policy_key == "P29_WISP":
            relevant = findings[:10]
        else:
            relevant = findings[:5]
    else:
        relevant = []
        for f in findings:
            text = f"{f.get('title', '')} {f.get('description', '')} {f.get('category', '')}".lower()
            if any(kw in text for kw in keywords):
                relevant.append(f)
        # Always include at least the top findings if none matched
        if not relevant:
            relevant = findings[:3]

    return "; ".join(
        f"[{f.get('severity', 'MEDIUM')}] {f.get('title', 'Unknown')}: {f.get('description', '')[:120]}"
        for f in relevant[:8]
    )


def generate_policy(policy_key: str, client_profile: dict) -> str:
    """
    Generate a single policy document via Claude API.

    Args:
        policy_key: Key from POLICIES dict (e.g., "P29_WISP")
        client_profile: Dict with keys:
            company_name, industry, employee_count, locations,
            tech_environment, frameworks, findings (list)

    Returns:
        Complete policy document text (3000-5000 words).
    """
    if policy_key not in POLICIES:
        raise ValueError(f"Unknown policy: {policy_key}. Valid: {list(POLICIES.keys())}")

    policy_def = POLICIES[policy_key]
    company = client_profile["company_name"]
    industry = client_profile.get("industry", "Professional Services")
    employee_count = client_profile.get("employee_count", 15)
    locations = client_profile.get("locations", "1 office")
    tech_env = client_profile.get("tech_environment", "Standard office IT")
    frameworks = client_profile.get("frameworks", "NIST CSF")
    findings = client_profile.get("findings", [])

    relevant_findings = _get_relevant_findings(findings, policy_key)

    # Format the user prompt from POLICY_USER template
    user_msg = POLICY_USER.format(
        company_name=company,
        industry=industry,
        employee_count=str(employee_count),
        locations=locations,
        tech_environment=tech_env,
        frameworks=frameworks,
        relevant_findings=relevant_findings or "No specific findings — generate based on industry best practices.",
        policy_name=policy_def["name"],
        policy_description=policy_def["desc"],
    )

    # Check cache
    cache_kwargs = {
        "policy_key": policy_key,
        "company_name": company,
        "industry": industry,
        "employee_count": str(employee_count),
    }
    cache_k = _cache_key(f"POLICY_{policy_key}", cache_kwargs)
    cached = _cache_get(cache_k, ttl_hours=24 * 7)  # 7-day cache for policies
    if cached is not None:
        _log_cost(f"POLICY_{policy_key}", 0, 0, True, company)
        return cached

    # Call Claude API with streaming (policies are large, 4000+ tokens)
    client = _get_client()
    response_text = ""
    try:
        with client.messages.stream(
            model=MODEL,
            max_tokens=8192,
            system=POLICY_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        ) as stream:
            for text in stream.text_stream:
                response_text += text
        usage = stream.get_final_message().usage
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
    except Exception as e:
        logger.error(f"Policy generation failed for {policy_key}: {e}")
        raise

    # Cache and log
    _cache_set(cache_k, response_text)
    _log_cost(f"POLICY_{policy_key}", input_tokens, output_tokens, False, company)

    return response_text


def generate_core_policies(client_profile: dict) -> dict:
    """
    Generate the 9 core policies every client needs.
    Returns dict: {policy_key: document_text}
    """
    return _generate_policies(CORE_POLICIES, client_profile)


def generate_all_policies(client_profile: dict) -> dict:
    """
    Generate all 17 policies (excluding P45_CUSTOM).
    Returns dict: {policy_key: document_text}
    """
    all_keys = [k for k in POLICIES if k != "P45_CUSTOM"]
    return _generate_policies(all_keys, client_profile)


def _generate_policies(policy_keys: list, client_profile: dict) -> dict:
    """Generate multiple policies, logging progress."""
    results = {}
    total = len(policy_keys)
    company = client_profile.get("company_name", "Unknown")

    for i, key in enumerate(policy_keys):
        policy_def = POLICIES[key]
        print(f"  [{i+1}/{total}] {policy_def['name']}...", end=" ", flush=True)
        try:
            doc = generate_policy(key, client_profile)
            results[key] = doc
            word_count = len(doc.split())
            print(f"done ({word_count} words)")
        except Exception as e:
            logger.warning(f"Policy {key} failed for {company}: {e}")
            print(f"FAILED ({e})")

    return results


def save_policies(company_name: str, policies: dict, output_dir: Path = None) -> Path:
    """
    Save generated policy documents to disk.

    Args:
        company_name: Client company name
        policies: Dict from generate_core_policies/generate_all_policies
        output_dir: Directory to save into (default: client-deliverables/{company}/)

    Returns:
        Path to the policy output directory.
    """
    company_safe = company_name.replace(" ", "_").replace("&", "and")

    if output_dir is None:
        output_dir = Path("client-deliverables") / f"{company_safe}_{date.today().strftime('%Y%m%d')}"

    policy_dir = output_dir / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)

    saved_files = []
    for key, doc_text in policies.items():
        policy_def = POLICIES.get(key, {})
        policy_name = policy_def.get("name", key)

        # Clean filename: P29_WISP -> WISP.txt, P30_IRP -> IRP.txt
        filename = key.split("_", 1)[1] + ".txt" if "_" in key else key + ".txt"
        filepath = policy_dir / filename
        filepath.write_text(doc_text)
        saved_files.append(filepath)

    # Write index file
    index_path = policy_dir / "INDEX.md"
    lines = [
        f"# Policy Documents for {company_name}",
        f"Generated: {date.today().strftime('%Y-%m-%d')}",
        f"Total policies: {len(policies)}",
        "",
    ]
    for key in sorted(policies.keys()):
        policy_def = POLICIES.get(key, {})
        filename = key.lower().replace("p", "").replace("_", "-", 1) + ".txt"
        word_count = len(policies[key].split())
        lines.append(f"- [{policy_def.get('name', key)}]({filename}) ({word_count} words)")

    index_path.write_text("\n".join(lines))

    print(f"\n  Saved {len(saved_files)} policies to {policy_dir}/")
    return policy_dir


def build_client_profile(scan_data: dict, forge_data: dict, industry: str = "cpa",
                         employee_count: int = 15, contact_name: str = None,
                         contact_title: str = None, contact_email: str = None) -> dict:
    """
    Build a client_profile dict from scan_data + forge_data for policy generation.
    Convenience function used by deliver.py.
    """
    ctx = get_industry_context(industry)
    profile = forge_data.get("profile", {})
    findings = scan_data.get("archer", {}).get("findings", [])

    return {
        "company_name": scan_data.get("company_name", "Unknown Company"),
        "industry": ctx.get("label", industry),
        "employee_count": employee_count,
        "contact_name": contact_name or ctx.get("client_title", "Decision Maker"),
        "contact_title": contact_title or "",
        "contact_email": contact_email or "",
        "locations": profile.get("locations", "1 office"),
        "tech_environment": profile.get("tech_environment",
                                        f"Standard {ctx.get('label', 'business')} IT environment"),
        "frameworks": ", ".join(profile.get("applicable_frameworks", [ctx.get("frameworks", "NIST CSF")])),
        "findings": findings,
    }
