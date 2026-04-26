"""
Apex (Pensar) execution runner.

Hard control model — read this before changing anything:

  1. Apex runs ONLY on our infrastructure (DigComply runner host or its
     Kali container). The customer's environment is never touched directly.
  2. The Pensar Apex binary + license belong to DigComply. We never ship
     the binary or credentials to customers.
  3. The runner is invoked ONLY by the operator route
     `POST /api/operator/clients/{cid}/validations/{eid}/run-apex`,
     which requires dashboard auth + (when configured) operator TOTP MFA.
  4. The customer cannot trigger a run. The customer can only:
        - sign the legal authorization scope (out-of-band + portal)
        - engage the kill switch on a running engagement
        - read advisor-validated findings AFTER advisor sign-off
  5. Before subprocess execution, the runner re-checks the legal
     authorization gate. If anything in the legal stack expired between
     approval and run, the run is refused.
  6. The runner enforces a wall-clock timeout, polls the engagement
     for kill-switch state on a fixed interval, and writes every byte
     of stdout/stderr to a per-engagement log on our disk.
  7. Findings are NOT shown to the customer until they pass FP review
     AND advisor validation, both of which are operator-only actions.

If you are tempted to add a customer-facing button that triggers Apex,
stop and re-read items 3 and 4.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import legal_authorization as _legal
import security_validation as _sv


# ─── Hard limits ──────────────────────────────────────────────

# Wall-clock cap for any single Apex invocation. Exists so a stuck or
# misbehaving run cannot consume our infrastructure indefinitely.
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("APEX_TIMEOUT_SECONDS", "3600"))   # 1 hour

# How often the runner polls the engagement record for kill-switch state.
KILL_SWITCH_POLL_SECONDS = 5

# Cap on captured output bytes (defensive; Apex output should be ≪ 50 MB).
MAX_LOG_BYTES = 50 * 1024 * 1024


class ApexRunError(Exception):
    """Raised when the runner refuses to invoke or execution fails before
    the legal gate opens."""


# ─── Internal helpers ────────────────────────────────────────

def _engagement_dir(client_id: str, engagement_id: str) -> Path:
    p = Path(os.getenv("DATA_DIR", ".")) / "clients" / client_id \
        / "security_validations" / engagement_id
    p.mkdir(parents=True, exist_ok=True)
    return p


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check_legal_gate(client_id: str) -> None:
    """Re-check the live legal authorization gate. The engagement may have
    been approved hours ago; we reject if anything has expired since."""
    try:
        import client_manager
    except Exception:
        client_manager = None
    raw = (client_manager.get_legal_authorization(client_id)
           if client_manager else {})
    rec = _legal.from_dict(raw if raw else {"client_id": client_id})
    gate = _legal.authorization_gate(rec, require_active=True)
    if not gate["allowed"]:
        raise ApexRunError(
            "Apex run refused — legal authorization gate is not currently "
            "open: " + "; ".join(gate["blockers"])
        )


def _ensure_binary(bin_: str) -> None:
    import shutil
    if not shutil.which(bin_):
        raise ApexRunError(
            f"Apex binary {bin_!r} not found on PATH. The Pensar Apex "
            "license + binary must be installed on the runner host before "
            "an active validation can be executed."
        )


# ─── Runner ──────────────────────────────────────────────────

def run_engagement(
    client_id: str, engagement_id: str, *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    operator_name: str = "operator",
) -> dict[str, Any]:
    """
    Execute the engagement's Apex command. Operator-only. Never invoked
    by customer-facing code paths.

    Steps (in this exact order):
      1. Load engagement, verify scan_class == SCAN_ACTIVE.
      2. Verify engagement.status == RUNNING (so the lifecycle
         transition has already been recorded by start_engagement).
      3. Re-check the legal authorization gate against the live record.
      4. Verify the Apex binary is on PATH and a scope file exists.
      5. Compose the command via build_apex_command (re-derived; we don't
         trust a stale stored command string).
      6. Spawn subprocess with no shell, captured stdout+stderr.
      7. Poll the engagement record every KILL_SWITCH_POLL_SECONDS for
         the kill switch; SIGTERM (then SIGKILL) the process if engaged.
      8. Enforce a wall-clock timeout.
      9. Persist stdout/stderr (truncated to MAX_LOG_BYTES) to disk and
         the exit code on the engagement.
     10. Audit the run.

    Findings ingestion is the operator's next step (parsing Apex output
    is left to a separate pipeline so we never claim Apex findings as
    customer-visible without the standard FP review + advisor validation).
    """
    # 1. Load + sanity-check.
    eng_dict = _sv.get_engagement(client_id, engagement_id)
    if eng_dict.get("scan_class") != _sv.SCAN_ACTIVE:
        raise ApexRunError("Apex only runs against active engagements")
    if eng_dict.get("status") != _sv.RUNNING:
        raise ApexRunError(
            f"Engagement must be in {_sv.RUNNING!r} state; "
            f"current status={eng_dict.get('status')!r}"
        )
    if eng_dict.get("kill_switch_engaged"):
        raise ApexRunError("Kill switch is engaged — refusing to start Apex")

    # 2. Re-check legal gate at execution time.
    _check_legal_gate(client_id)

    # 3. Make sure binary is present.
    bin_ = os.getenv("APEX_BIN", "pensar")
    _ensure_binary(bin_)

    # 4. Make sure a scope file exists (operator should have called
    #    attach_apex_command at scope time; do it now if not).
    if not eng_dict.get("apex_scope_file"):
        _sv.attach_apex_command(client_id, engagement_id, dry_run=True)
        eng_dict = _sv.get_engagement(client_id, engagement_id)

    # 5. Compose command.
    cmd_str = _sv.build_apex_command(eng_dict, dry_run=False)
    if not cmd_str:
        raise ApexRunError("Could not compose Apex command (missing target?)")
    cmd = shlex.split(cmd_str)

    # 6. Set up log file.
    log_path = _engagement_dir(client_id, engagement_id) / "apex.log"
    _record_run_start(client_id, engagement_id, cmd_str, str(log_path),
                       operator_name=operator_name)

    # 7. Spawn subprocess WITHOUT a shell. Pin a sanitized environment so
    #    we don't accidentally pass operator credentials to Apex.
    env = {
        "PATH": os.getenv("PATH", ""),
        "HOME": os.getenv("HOME", "/tmp"),
        "ANTHROPIC_API_KEY": os.getenv("APEX_ANTHROPIC_API_KEY", ""),
        # WANDB tracing is optional and pass-through.
        "WANDB_API_KEY": os.getenv("WANDB_API_KEY", ""),
        "WANDB_ENTITY": os.getenv("WANDB_ENTITY", ""),
        "WANDB_PROJECT": os.getenv("WANDB_PROJECT", "apex-traces"),
    }
    started_at = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env=env, shell=False,
            start_new_session=True,
        )
    except FileNotFoundError as e:
        raise ApexRunError(f"Apex binary failed to launch: {e}")

    # 8. Concurrent monitor: kill-switch + timeout.
    abort_reason = {"reason": ""}

    def _monitor():
        while proc.poll() is None:
            time.sleep(KILL_SWITCH_POLL_SECONDS)
            try:
                cur = _sv.get_engagement(client_id, engagement_id)
            except Exception:
                continue
            if cur.get("kill_switch_engaged"):
                abort_reason["reason"] = "kill_switch_engaged"
                _terminate(proc)
                return
            if (time.monotonic() - started_at) > timeout_seconds:
                abort_reason["reason"] = "timeout"
                _terminate(proc)
                return

    monitor = threading.Thread(target=_monitor, daemon=True)
    monitor.start()

    # 9. Drain output to log file with size cap.
    bytes_written = 0
    truncated = False
    try:
        with open(log_path, "wb") as logf:
            assert proc.stdout is not None
            for chunk in iter(lambda: proc.stdout.read(8192), b""):
                if not chunk:
                    break
                if bytes_written + len(chunk) > MAX_LOG_BYTES:
                    chunk = chunk[: MAX_LOG_BYTES - bytes_written]
                    truncated = True
                if chunk:
                    logf.write(chunk)
                    bytes_written += len(chunk)
                if truncated:
                    abort_reason["reason"] = abort_reason["reason"] or "log_size_cap"
                    _terminate(proc)
                    break
    except Exception:
        pass

    exit_code = proc.wait()
    monitor.join(timeout=2)
    duration = round(time.monotonic() - started_at, 1)
    reason = abort_reason["reason"] or ("ok" if exit_code == 0 else f"exit_{exit_code}")

    # 10. Persist results + audit.
    _record_run_end(client_id, engagement_id,
                     exit_code=exit_code, log_path=str(log_path),
                     duration_s=duration, reason=reason,
                     truncated=truncated)
    return {
        "engagement_id": engagement_id,
        "exit_code": exit_code,
        "reason": reason,
        "duration_s": duration,
        "log_path": str(log_path),
        "log_truncated": truncated,
    }


def _terminate(proc: subprocess.Popen) -> None:
    """Kill the Apex process group (Apex may spawn helpers)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    # Hard-kill after 10 s if still alive.
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _record_run_start(client_id: str, engagement_id: str,
                       cmd: str, log_path: str, *, operator_name: str) -> None:
    eng = _sv._load(client_id, engagement_id)
    eng.apex_run_id = "apex_" + str(int(time.time()))
    eng.apex_command = cmd
    eng.apex_log_path = log_path
    eng.apex_started_at = _now_iso()
    eng.apex_ended_at = ""
    eng.apex_exit_code = 0
    _sv._audit(eng, "apex_run_started", by=operator_name, command=cmd)
    _sv._save(eng)
    try:
        import audit_log as _al
        _al.record(
            action="apex_run_started",
            actor=operator_name, role=_al.ROLE_OPERATOR,
            client_id=client_id, command=cmd, engagement_id=engagement_id,
        )
    except Exception:
        pass


def _record_run_end(client_id: str, engagement_id: str, *,
                     exit_code: int, log_path: str, duration_s: float,
                     reason: str, truncated: bool) -> None:
    eng = _sv._load(client_id, engagement_id)
    eng.apex_exit_code = exit_code
    eng.apex_log_path = log_path
    eng.apex_ended_at = _now_iso()
    _sv._audit(eng, "apex_run_ended",
                exit_code=exit_code, reason=reason,
                duration_s=duration_s, log_truncated=truncated)
    _sv._save(eng)
    try:
        import audit_log as _al
        _al.record(
            action="apex_run_ended",
            actor="runner", role=_al.ROLE_SYSTEM,
            client_id=client_id, engagement_id=engagement_id,
            exit_code=exit_code, reason=reason,
            duration_s=duration_s, log_truncated=truncated,
        )
    except Exception:
        pass
