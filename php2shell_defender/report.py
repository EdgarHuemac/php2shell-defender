"""
report.py
----------
Turns ini_auditor.CheckResult lists and version_db.VersionVerdict objects
into human-readable or machine-readable reports, and can emit a ready-to-
apply php.ini remediation snippet.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .ini_auditor import CheckResult, Status, Severity
from .version_db import VersionVerdict, ADVISORY_REFERENCE

RESET = "\033[0m"
COLORS = {
    Status.PASS: "\033[32m",     # green
    Status.WARN: "\033[33m",     # yellow
    Status.FAIL: "\033[31m",     # red
    Status.UNKNOWN: "\033[36m",  # cyan
    Status.INFO: "\033[37m",     # grey
}
VERDICT_COLORS = {
    "patched": "\033[32m",
    "vulnerable": "\033[31m",
    "eol": "\033[35m",
    "unknown": "\033[36m",
}

_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


def compute_risk_score(results: list[CheckResult], verdict: Optional[VersionVerdict]) -> dict:
    """
    Simple additive risk score: every FAIL/WARN contributes its severity
    weight. This is a triage heuristic, not a formal CVSS-style score --
    it exists to let you sort many hosts by "which needs attention first".
    """
    score = 0
    for r in results:
        if r.status in (Status.FAIL, Status.WARN):
            score += _SEVERITY_WEIGHT[r.severity]

    if verdict is not None:
        if verdict.status == "vulnerable":
            score += 50
        elif verdict.status == "eol":
            score += 60
        elif verdict.status == "unknown":
            score += 10

    if score == 0:
        band = "LOW"
    elif score < 20:
        band = "LOW"
    elif score < 50:
        band = "MEDIUM"
    elif score < 90:
        band = "HIGH"
    else:
        band = "CRITICAL"

    return {"score": score, "band": band}


def render_text(
    results: list[CheckResult],
    verdict: Optional[VersionVerdict],
    target: str,
    use_color: bool = True,
) -> str:
    def c(status_or_key, text):
        if not use_color:
            return text
        color = COLORS.get(status_or_key) if isinstance(status_or_key, Status) else VERDICT_COLORS.get(status_or_key, "")
        return f"{color}{text}{RESET}" if color else text

    lines = []
    lines.append("=" * 72)
    lines.append(f" PHP2Shell-Defender  —  Hardening & Version Audit")
    lines.append(f" Target: {target}")
    lines.append(f" Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("=" * 72)

    lines.append("")
    lines.append("-- Version Fingerprint " + "-" * 48)
    if verdict is None:
        lines.append("  No version information evaluated for this run.")
    else:
        status_label = verdict.status.upper()
        lines.append(f"  Raw string:      {verdict.raw_version}")
        lines.append(f"  Parsed version:  {'.'.join(map(str, verdict.parsed)) if verdict.parsed else 'n/a'}")
        lines.append(f"  Branch:          {verdict.branch_str or 'n/a'}")
        lines.append(f"  Status:          {c(verdict.status, status_label)}")
        if verdict.patched_target_str:
            lines.append(f"  Patched target:  {verdict.patched_target_str}")
        lines.append(f"  Detail:          {verdict.detail}")

    lines.append("")
    lines.append("-- Configuration Checks " + "-" * 47)
    for r in results:
        lines.append(f"  [{c(r.status, r.status.value):>14}] {r.key}")
        lines.append(f"      current:  {r.current_value if r.current_value is not None else '(not set)'}")
        lines.append(f"      expected: {r.expected}")
        if r.status in (Status.FAIL, Status.WARN, Status.UNKNOWN):
            lines.append(f"      fix:      {r.recommendation}")
        lines.append(f"      why:      {r.advisory_relevance}")
        lines.append("")

    risk = compute_risk_score(results, verdict)
    lines.append("-- Summary " + "-" * 60)
    fail_n = sum(1 for r in results if r.status == Status.FAIL)
    warn_n = sum(1 for r in results if r.status == Status.WARN)
    pass_n = sum(1 for r in results if r.status == Status.PASS)
    unk_n = sum(1 for r in results if r.status == Status.UNKNOWN)
    lines.append(f"  Checks:  {pass_n} pass / {warn_n} warn / {fail_n} fail / {unk_n} unknown")
    lines.append(f"  Risk:    {risk['score']} ({risk['band']})")
    lines.append("")
    lines.append(f"  Advisory refs: {', '.join(ADVISORY_REFERENCE['cve_ids'])}")
    lines.append(f"  Note: {ADVISORY_REFERENCE['note']}")
    lines.append("=" * 72)

    return "\n".join(lines)


def render_json(
    results: list[CheckResult],
    verdict: Optional[VersionVerdict],
    target: str,
) -> str:
    risk = compute_risk_score(results, verdict)
    payload = {
        "tool": "php2shell-defender",
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "advisory": ADVISORY_REFERENCE,
        "version": (
            {
                "raw": verdict.raw_version,
                "parsed": list(verdict.parsed) if verdict.parsed else None,
                "branch": list(verdict.branch) if verdict.branch else None,
                "status": verdict.status,
                "patched_target": list(verdict.patched_target) if verdict.patched_target else None,
                "detail": verdict.detail,
            }
            if verdict
            else None
        ),
        "checks": [
            {
                "key": r.key,
                "status": r.status.value,
                "severity": r.severity.value,
                "current_value": r.current_value,
                "expected": r.expected,
                "recommendation": r.recommendation,
                "advisory_relevance": r.advisory_relevance,
            }
            for r in results
        ],
        "risk": risk,
    }
    return json.dumps(payload, indent=2)


def render_markdown(
    results: list[CheckResult],
    verdict: Optional[VersionVerdict],
    target: str,
) -> str:
    risk = compute_risk_score(results, verdict)
    lines = [f"# PHP2Shell-Defender Report — {target}", ""]
    lines.append(f"_Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}_")
    lines.append("")

    lines.append("## Version Fingerprint")
    if verdict is None:
        lines.append("No version information evaluated for this run.")
    else:
        lines.append(f"- **Raw string:** `{verdict.raw_version}`")
        lines.append(f"- **Branch:** {verdict.branch_str or 'n/a'}")
        lines.append(f"- **Status:** **{verdict.status.upper()}**")
        if verdict.patched_target_str:
            lines.append(f"- **Patched target:** `{verdict.patched_target_str}`")
        lines.append(f"- {verdict.detail}")
    lines.append("")

    lines.append("## Configuration Checks")
    lines.append("")
    lines.append("| Status | Directive | Current | Expected |")
    lines.append("|---|---|---|---|")
    for r in results:
        current = r.current_value if r.current_value is not None else "_(not set)_"
        lines.append(f"| {r.status.value} | `{r.key}` | `{current}` | {r.expected} |")
    lines.append("")

    lines.append("### Remediation detail")
    for r in results:
        if r.status in (Status.FAIL, Status.WARN, Status.UNKNOWN):
            lines.append(f"- **`{r.key}`** ({r.status.value}, {r.severity.value}): {r.recommendation}")
            lines.append(f"  - *Why it matters:* {r.advisory_relevance}")
    lines.append("")

    lines.append(f"## Risk score: {risk['score']} ({risk['band']})")
    lines.append("")
    lines.append(f"Advisory refs: {', '.join(ADVISORY_REFERENCE['cve_ids'])}")
    lines.append(f"> {ADVISORY_REFERENCE['note']}")

    return "\n".join(lines)


def render_ini_snippet(results: list[CheckResult]) -> str:
    """
    Emit a ready-to-paste php.ini snippet that fixes every FAIL/WARN/UNKNOWN
    directive this run found, with a comment explaining each line.
    """
    lines = [
        "; ---------------------------------------------------------------",
        "; php2shell-defender recommended hardening snippet",
        f"; Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "; Review each value against your application's actual needs",
        "; before applying -- these are sane defaults, not guarantees.",
        "; ---------------------------------------------------------------",
        "",
    ]

    defaults = {
        "session.upload_progress.enabled": "0",
        "display_errors": "Off",
        "fatal_error_backtraces": "0",
        "post_max_size": "16M",
        "memory_limit": "256M",
        "expose_php": "Off",
        "log_errors": "On",
    }

    touched = False
    for r in results:
        if r.status in (Status.FAIL, Status.WARN, Status.UNKNOWN) and r.key in defaults:
            lines.append(f"; {r.description} -- was: {r.current_value!r}")
            lines.append(f"{r.key} = {defaults[r.key]}")
            lines.append("")
            touched = True

    if not touched:
        lines.append("; No changes needed -- all audited directives already pass.")

    return "\n".join(lines)
