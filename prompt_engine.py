"""
CyberComply — AI Prompt Engine
Wraps the Anthropic Claude API with caching, cost tracking, and retry logic.
"""

from __future__ import annotations

import os
import json
import hashlib
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta

from dotenv import load_dotenv
import anthropic

from prompt_library import PROMPTS, INDUSTRY_CONTEXT

load_dotenv()

logger = logging.getLogger("prompt_engine")

# ─── Configuration ────────────────────────────────────────
MODEL = "claude-sonnet-4-6"
CACHE_DIR = Path(os.getenv("CACHE_DIR", ".prompt_cache"))
LOG_FILE = Path(os.getenv("LOG_FILE", "prompt_log.jsonl"))
CACHE_TTL_HOURS = 24
INDUSTRY_CACHE_FILE = Path("industry_cache.json")

# Cost per 1M tokens (claude-sonnet-4-6)
COST_INPUT_PER_M = 3.0
COST_OUTPUT_PER_M = 15.0

# ─── Client ───────────────────────────────────────────────
_client = None

def _get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(max_retries=3)
    return _client


# ─── Cache helpers ────────────────────────────────────────
def _cache_key(prompt_id: str, kwargs: dict) -> str:
    raw = json.dumps({"prompt_id": prompt_id, **dict(sorted(kwargs.items()))}, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_get(key: str, ttl_hours: int = CACHE_TTL_HOURS) -> str | None:
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = datetime.fromisoformat(data["cached_at"])
        if datetime.now() - cached_at > timedelta(hours=ttl_hours):
            path.unlink()
            return None
        return data["response"]
    except (json.JSONDecodeError, KeyError):
        return None


def _cache_set(key: str, response: str):
    CACHE_DIR.mkdir(exist_ok=True)
    path = CACHE_DIR / f"{key}.json"
    path.write_text(json.dumps({
        "cached_at": datetime.now().isoformat(),
        "response": response,
    }))


# ─── Cost logging ─────────────────────────────────────────
def _log_cost(prompt_id: str, input_tokens: int, output_tokens: int, cached: bool, client_name: str = ""):
    cost = (input_tokens / 1_000_000 * COST_INPUT_PER_M) + (output_tokens / 1_000_000 * COST_OUTPUT_PER_M)
    entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt_id": prompt_id,
        "client": client_name,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": round(cost, 6),
        "cached": cached,
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.warning(f"Failed to write cost log: {e}")
    return cost


# ─── Core API call ────────────────────────────────────────
def call_prompt(prompt_id: str, client_name: str = "", use_cache: bool = True,
                stream: bool = False, **kwargs) -> str:
    """
    Look up a prompt by ID, format with kwargs, call Claude API, return response text.
    Logs cost to prompt_log.jsonl. Caches results by default.
    """
    if prompt_id not in PROMPTS:
        raise ValueError(f"Unknown prompt ID: {prompt_id}")

    prompt_def = PROMPTS[prompt_id]
    system_msg = prompt_def["system"]
    user_msg = prompt_def["user"].format(**kwargs)

    # Check cache
    cache_k = _cache_key(prompt_id, kwargs)
    if use_cache:
        ttl = 24 * 30 if prompt_id == "P00_INDUSTRY_CONTEXT" else CACHE_TTL_HOURS
        cached = _cache_get(cache_k, ttl_hours=ttl)
        if cached is not None:
            _log_cost(prompt_id, 0, 0, True, client_name)
            return cached

    client = _get_client()

    if stream:
        # Streaming for large responses
        response_text = ""
        with client.messages.stream(
            model=MODEL,
            max_tokens=4096,
            system=system_msg,
            messages=[{"role": "user", "content": user_msg}],
        ) as stream_resp:
            for text in stream_resp.text_stream:
                response_text += text
        usage = stream_resp.get_final_message().usage
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
    else:
        response = client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=system_msg,
            messages=[{"role": "user", "content": user_msg}],
        )
        response_text = response.content[0].text
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens

    # Cache and log
    if use_cache:
        _cache_set(cache_k, response_text)
    _log_cost(prompt_id, input_tokens, output_tokens, False, client_name)

    return response_text


def call_prompt_json(prompt_id: str, client_name: str = "", **kwargs) -> dict:
    """
    Same as call_prompt but parses JSON response.
    Falls back to regex extraction if json.loads fails.
    """
    import re
    text = call_prompt(prompt_id, client_name=client_name, **kwargs)

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting JSON from markdown code blocks
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding first { ... } block
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from prompt {prompt_id} response: {text[:200]}...")


# ─── Industry context ────────────────────────────────────
# Keyword mapping for fuzzy match
_INDUSTRY_KEYWORDS = {
    "cpa": ["cpa", "accounting", "accountant", "tax preparation", "tax preparer", "bookkeeping"],
    "healthcare": ["healthcare", "medical", "hospital", "clinic", "physician", "dental", "pharmacy"],
    "legal": ["legal", "law firm", "attorney", "lawyer", "paralegal"],
    "financial": ["financial", "wealth management", "ria", "investment", "broker", "banking", "fintech"],
    "saas": ["saas", "software", "technology", "tech", "startup", "app"],
    "government": ["government", "defense", "govcon", "dod", "federal", "contractor"],
    "nonprofit": ["nonprofit", "non-profit", "ngo", "charity", "foundation"],
    "education": ["education", "school", "university", "college", "edtech"],
    "manufacturing": ["manufacturing", "industrial", "factory", "production"],
    "real_estate": ["real estate", "title", "mortgage", "property", "realtor", "broker"],
}


def get_industry_context(industry_key: str, company_description: str = None) -> dict:
    """
    Get industry context dict. Tries exact match, fuzzy match, AI generation, then fallback.
    Generated contexts are cached both in-memory and to disk.
    """
    # Exact match
    key_lower = industry_key.lower().strip()
    if key_lower in INDUSTRY_CONTEXT:
        return INDUSTRY_CONTEXT[key_lower]

    # Fuzzy match via keywords (whole-word matching to avoid false positives)
    key_words = set(key_lower.split())
    for ctx_key, keywords in _INDUSTRY_KEYWORDS.items():
        for kw in keywords:
            # Multi-word keywords: check substring. Single-word: check word boundary.
            if " " in kw:
                if kw in key_lower:
                    return INDUSTRY_CONTEXT[ctx_key]
            elif kw in key_words:
                return INDUSTRY_CONTEXT[ctx_key]

    # Fuzzy match — check if key is substring of any label
    for ctx_key, ctx in INDUSTRY_CONTEXT.items():
        if key_lower in ctx["label"].lower():
            return ctx

    # AI generation if company_description provided
    if company_description:
        # Check local cache file
        cache = {}
        if INDUSTRY_CACHE_FILE.exists():
            try:
                cache = json.loads(INDUSTRY_CACHE_FILE.read_text())
            except json.JSONDecodeError:
                pass

        cache_k = hashlib.sha256(company_description.encode()).hexdigest()[:16]
        if cache_k in cache:
            # Also persist in-memory for this session
            INDUSTRY_CONTEXT[key_lower] = cache[cache_k]
            return cache[cache_k]

        try:
            result = call_prompt_json(
                "P00_INDUSTRY_CONTEXT",
                company_description=company_description,
                company_name=industry_key,
                domain="unknown",
            )
            # Cache to disk
            cache[cache_k] = result
            INDUSTRY_CACHE_FILE.write_text(json.dumps(cache, indent=2))
            # Cache in-memory so subsequent calls in this session are instant
            INDUSTRY_CONTEXT[key_lower] = result
            return result
        except Exception as e:
            logger.warning(f"AI industry context generation failed: {e}")

    # Ultimate fallback
    return INDUSTRY_CONTEXT["general"]


# ─── Cost estimation ──────────────────────────────────────
def estimate_cost(prompt_id: str, **kwargs) -> float:
    """
    Estimate cost of a prompt call without calling the API.
    Uses heuristic: ~4 chars per token for English text.
    """
    if prompt_id not in PROMPTS:
        raise ValueError(f"Unknown prompt ID: {prompt_id}")

    prompt_def = PROMPTS[prompt_id]
    system_text = prompt_def["system"]
    user_text = prompt_def["user"].format(**kwargs) if kwargs else prompt_def["user"]

    # Rough token estimation: ~4 chars per token
    input_tokens = (len(system_text) + len(user_text)) / 4
    # Estimate output as 2x input for narratives, capped at 4096
    output_tokens = min(input_tokens * 2, 4096)

    cost = (input_tokens / 1_000_000 * COST_INPUT_PER_M) + (output_tokens / 1_000_000 * COST_OUTPUT_PER_M)
    return round(cost, 6)


def get_total_cost() -> dict:
    """Read the cost log and return summary."""
    if not LOG_FILE.exists():
        return {"total_cost": 0, "total_calls": 0, "cached_calls": 0}

    total_cost = 0
    total_calls = 0
    cached_calls = 0
    for line in LOG_FILE.read_text().strip().split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
            total_cost += entry.get("cost_usd", 0)
            total_calls += 1
            if entry.get("cached"):
                cached_calls += 1
        except json.JSONDecodeError:
            continue

    return {
        "total_cost": round(total_cost, 4),
        "total_calls": total_calls,
        "cached_calls": cached_calls,
    }
