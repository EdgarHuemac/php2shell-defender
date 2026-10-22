"""
ini_auditor.py
---------------
Parses php.ini-style configuration (a real php.ini file, a `php -i`
dump, or a hand-typed key=value list) and audits it against the
mitigations recommended for the PHP2Shell advisory.

Nothing here touches a network or a running server -- it is a static
config file / text parser plus a rule engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Status(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CheckResult:
    key: str
    description: str
    status: Status
    severity: Severity
    current_value: Optional[str]
    expected: str
    recommendation: str
    advisory_relevance: str


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

_LINE_RE = re.compile(
    r"""^\s*
        (?P<key>[A-Za-z0-9_.\[\]]+)
        \s*=\s*
        (?P<value>.*?)
        \s*$
    """,
    re.VERBOSE,
)


def parse_ini_text(text: str) -> dict[str, str]:
    """
    Minimal, tolerant php.ini parser.

    php.ini is not strict INI: it allows unquoted values, ';' and '#'
    comments, optional quoting, and section headers like [PHP] that we
    simply ignore (directives are looked up by bare key regardless of
    section). This is intentionally permissive rather than a full
    grammar -- good enough to reliably pull out the handful of
    directives this tool audits.
    """
    settings: dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            continue  # section header, e.g. [PHP]

        match = _LINE_RE.match(line)
        if not match:
            continue

        key = match.group("key").strip()
        value = match.group("value").strip()

        # Strip inline comments that weren't on their own line
        # (php.ini allows `key = value ; comment`)
        if ";" in value and not value.startswith('"'):
            value = value.split(";", 1)[0].strip()

        # Strip surrounding quotes
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]

        settings[key] = value

    return settings


def load_ini_file(path: str | Path) -> dict[str, str]:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_ini_text(text)


def parse_kv_pairs(pairs: list[str]) -> dict[str, str]:
    """Parse ['key=value', 'key2=value2'] from --set CLI args."""
    settings: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        settings[key.strip()] = value.strip()
    return settings


# --------------------------------------------------------------------------
# Value interpretation helpers
# --------------------------------------------------------------------------

_TRUTHY = {"1", "on", "true", "yes"}
_FALSY = {"0", "off", "false", "no", ""}


def _is_off(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _FALSY


def _is_on(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _TRUTHY


def parse_byte_size(value: str) -> Optional[int]:
    """
    Parse a php.ini shorthand byte value like '8M', '256K', '2G', '0', '-1'.
    Returns bytes as int, or None if unparseable. '-1' (unlimited) and '0'
    (also unlimited/disabled depending on directive) are returned as-is
    (negative / zero) so callers can branch on them explicitly.
    """
    if value is None:
        return None
    v = value.strip()
    if v in ("-1", ""):
        return -1
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMGkmg]?)$", v)
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2).upper()
    multiplier = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[unit]
    return int(number * multiplier)


def format_bytes(n: int) -> str:
    if n < 0:
        return "unlimited"
    for unit, size in (("G", 1024**3), ("M", 1024**2), ("K", 1024)):
        if n >= size:
            return f"{n / size:.0f}{unit}"
    return f"{n}B"


# --------------------------------------------------------------------------
# Individual checks
# --------------------------------------------------------------------------
# Reasonable upper bounds used only to flag *unusually* generous settings --
# these are heuristics for a hardening review, not hard compliance limits.
_SANE_MAX_POST_MAX_SIZE = 64 * 1024 * 1024        # 64M
_SANE_MAX_MEMORY_LIMIT = 512 * 1024 * 1024        # 512M


def check_upload_progress(settings: dict[str, str]) -> CheckResult:
    key = "session.upload_progress.enabled"
    value = settings.get(key)

    if value is None:
        return CheckResult(
            key=key,
            description="session.upload_progress.enabled",
            status=Status.UNKNOWN,
            severity=Severity.HIGH,
            current_value=None,
            expected="0 / Off",
            recommendation=f"Directive not found in supplied config. Default is 'On' in most "
                            f"distributions -- set `{key} = 0` explicitly in php.ini.",
            advisory_relevance=(
                "The upload-progress exhaustion issue (CVE-2026-109618) relies on "
                "session.upload_progress hooks being active. Disabling it removes "
                "the vulnerable code path entirely as an interim mitigation."
            ),
        )

    if _is_off(value):
        return CheckResult(
            key=key,
            description="session.upload_progress.enabled",
            status=Status.PASS,
            severity=Severity.HIGH,
            current_value=value,
            expected="0 / Off",
            recommendation="No action needed -- directive is correctly disabled.",
            advisory_relevance=(
                "Upload-progress tracking is disabled, which removes the code path "
                "targeted by CVE-2026-109618 as an interim mitigation."
            ),
        )

    return CheckResult(
        key=key,
        description="session.upload_progress.enabled",
        status=Status.FAIL,
        severity=Severity.HIGH,
        current_value=value,
        expected="0 / Off",
        recommendation=f"Set `{key} = 0` in php.ini and restart/reload PHP-FPM or Apache.",
        advisory_relevance=(
            "Upload-progress tracking is ACTIVE. Until the engine is patched to "
            "8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (as applicable), this leaves the "
            "worker-memory-state exhaustion path (CVE-2026-109618) reachable."
        ),
    )


def check_display_errors(settings: dict[str, str]) -> CheckResult:
    key = "display_errors"
    value = settings.get(key)

    if value is None:
        return CheckResult(
            key=key, description="display_errors", status=Status.UNKNOWN,
            severity=Severity.MEDIUM, current_value=None, expected="0 / Off",
            recommendation=f"Directive not found. Confirm `{key} = Off` is set for production.",
            advisory_relevance=(
                "Verbose errors can leak internal state (paths, stack frames, "
                "occasionally heap-adjacent data) that is useful to an attacker "
                "probing for the memory-disclosure behavior described in the "
                "advisory (CVE-2026-109619)."
            ),
        )

    if _is_off(value):
        return CheckResult(
            key=key, description="display_errors", status=Status.PASS,
            severity=Severity.MEDIUM, current_value=value, expected="0 / Off",
            recommendation="No action needed.",
            advisory_relevance="Error detail is not exposed to clients.",
        )

    return CheckResult(
        key=key, description="display_errors", status=Status.FAIL,
        severity=Severity.MEDIUM, current_value=value, expected="0 / Off",
        recommendation=f"Set `{key} = Off` in production php.ini. Keep `log_errors = On` "
                        f"and send errors to a log file instead via `error_log`.",
        advisory_relevance=(
            "Errors are rendered to clients. Combined with the advisory's "
            "memory-disclosure behavior, this increases the chance that leaked "
            "heap data or internal paths become directly visible to a remote "
            "attacker rather than staying server-side."
        ),
    )


def check_fatal_error_backtraces(settings: dict[str, str]) -> CheckResult:
    key = "fatal_error_backtraces"
    value = settings.get(key)

    if value is None:
        return CheckResult(
            key=key, description="fatal_error_backtraces", status=Status.UNKNOWN,
            severity=Severity.LOW, current_value=None, expected="0 / Off (production)",
            recommendation=f"Directive not found (available PHP 8.3+). If present in your "
                            f"version, set `{key} = 0` for internet-facing production hosts.",
            advisory_relevance=(
                "Backtraces on fatal errors can surface function arguments and "
                "internal structure that aid an attacker refining a probe against "
                "the engine's request-parsing state."
            ),
        )

    if _is_off(value):
        return CheckResult(
            key=key, description="fatal_error_backtraces", status=Status.PASS,
            severity=Severity.LOW, current_value=value, expected="0 / Off (production)",
            recommendation="No action needed.",
            advisory_relevance="Backtrace detail is suppressed on fatal errors.",
        )

    return CheckResult(
        key=key, description="fatal_error_backtraces", status=Status.WARN,
        severity=Severity.LOW, current_value=value, expected="0 / Off (production)",
        recommendation=f"Consider setting `{key} = 0` on production/internet-facing hosts. "
                        f"Keep it On only in dedicated debug/staging environments.",
        advisory_relevance=(
            "Backtraces are enabled, which is useful in debugging but widens the "
            "information available to someone probing error-handling behavior."
        ),
    )


def check_post_max_size(settings: dict[str, str]) -> CheckResult:
    key = "post_max_size"
    value = settings.get(key)

    if value is None:
        return CheckResult(
            key=key, description="post_max_size", status=Status.UNKNOWN,
            severity=Severity.MEDIUM, current_value=None, expected="bounded, e.g. 8M-32M",
            recommendation="Directive not found. Set an explicit, bounded value appropriate "
                            "to your application's legitimate upload needs.",
            advisory_relevance=(
                "post_max_size bounds the size of the multipart bodies an attacker "
                "can use when exercising upload-related code paths."
            ),
        )

    parsed = parse_byte_size(value)
    if parsed is None:
        return CheckResult(
            key=key, description="post_max_size", status=Status.UNKNOWN,
            severity=Severity.MEDIUM, current_value=value, expected="bounded, e.g. 8M-32M",
            recommendation=f"Could not parse value {value!r}. Confirm it is a valid php.ini size.",
            advisory_relevance="Unable to evaluate posture without a parseable value.",
        )

    if parsed == 0:
        return CheckResult(
            key=key, description="post_max_size", status=Status.FAIL,
            severity=Severity.HIGH, current_value=value, expected="bounded, e.g. 8M-32M",
            recommendation=f"`{key} = 0` disables the POST size limit entirely. Set an "
                            f"explicit bound (e.g. 16M) instead.",
            advisory_relevance=(
                "An unbounded POST size gives more room to construct the large, "
                "boundary-heavy multipart requests relevant to the advisory's "
                "memory-state probes, and increases worst-case resource exhaustion."
            ),
        )

    if parsed > _SANE_MAX_POST_MAX_SIZE:
        return CheckResult(
            key=key, description="post_max_size", status=Status.WARN,
            severity=Severity.LOW, current_value=value,
            expected=f"<= {format_bytes(_SANE_MAX_POST_MAX_SIZE)} unless genuinely required",
            recommendation="Confirm this large limit is actually required by the "
                            "application; tighten it if not.",
            advisory_relevance="A generous POST limit widens the practical attack surface "
                                "for large/complex multipart payloads.",
        )

    return CheckResult(
        key=key, description="post_max_size", status=Status.PASS,
        severity=Severity.LOW, current_value=value,
        expected=f"<= {format_bytes(_SANE_MAX_POST_MAX_SIZE)}",
        recommendation="No action needed.",
        advisory_relevance="POST size is explicitly bounded to a reasonable value.",
    )


def check_memory_limit(settings: dict[str, str]) -> CheckResult:
    key = "memory_limit"
    value = settings.get(key)

    if value is None:
        return CheckResult(
            key=key, description="memory_limit", status=Status.UNKNOWN,
            severity=Severity.MEDIUM, current_value=None, expected="bounded, e.g. 128M-256M",
            recommendation="Directive not found. Set an explicit bound appropriate to your "
                            "workload.",
            advisory_relevance=(
                "memory_limit caps how much worker memory a single request can "
                "consume before PHP kills it -- relevant containment for any "
                "memory-state issue, including the advisory's."
            ),
        )

    parsed = parse_byte_size(value)
    if parsed is None:
        return CheckResult(
            key=key, description="memory_limit", status=Status.UNKNOWN,
            severity=Severity.MEDIUM, current_value=value, expected="bounded, e.g. 128M-256M",
            recommendation=f"Could not parse value {value!r}.",
            advisory_relevance="Unable to evaluate posture without a parseable value.",
        )

    if parsed == -1:
        return CheckResult(
            key=key, description="memory_limit", status=Status.FAIL,
            severity=Severity.HIGH, current_value=value, expected="bounded, e.g. 128M-256M",
            recommendation=f"`{key} = -1` removes the per-request memory ceiling. Set an "
                            f"explicit bound (e.g. 256M) instead.",
            advisory_relevance=(
                "An unlimited memory ceiling removes a key containment backstop: if "
                "a worker is pushed into the advisory's abnormal-termination memory "
                "state, there is no PHP-level cap limiting how much it can consume "
                "before the OS/orchestrator intervenes."
            ),
        )

    if parsed > _SANE_MAX_MEMORY_LIMIT:
        return CheckResult(
            key=key, description="memory_limit", status=Status.WARN,
            severity=Severity.LOW, current_value=value,
            expected=f"<= {format_bytes(_SANE_MAX_MEMORY_LIMIT)} unless genuinely required",
            recommendation="Confirm this high ceiling is required; tighten it per-pool/per-vhost "
                            "if only specific endpoints need it.",
            advisory_relevance="A very high ceiling weakens containment value as a mitigation.",
        )

    return CheckResult(
        key=key, description="memory_limit", status=Status.PASS,
        severity=Severity.LOW, current_value=value,
        expected=f"<= {format_bytes(_SANE_MAX_MEMORY_LIMIT)}",
        recommendation="No action needed.",
        advisory_relevance="Per-request memory is explicitly bounded.",
    )


def check_expose_php(settings: dict[str, str]) -> CheckResult:
    """Bonus hardening check: hides version banner, slowing down recon."""
    key = "expose_php"
    value = settings.get(key)

    if value is None or _is_on(value):
        return CheckResult(
            key=key, description="expose_php", status=Status.WARN,
            severity=Severity.LOW, current_value=value or "On (default)",
            expected="0 / Off",
            recommendation=f"Set `{key} = Off` to stop PHP announcing its version via the "
                            f"X-Powered-By header.",
            advisory_relevance=(
                "Not a fix, but reduces how trivially an opportunistic scanner can "
                "identify a vulnerable version during the exposure window between "
                "PoC release and your patch rollout."
            ),
        )

    return CheckResult(
        key=key, description="expose_php", status=Status.PASS,
        severity=Severity.LOW, current_value=value, expected="0 / Off",
        recommendation="No action needed.",
        advisory_relevance="Version banner is suppressed, slightly raising recon cost.",
    )


def check_log_errors(settings: dict[str, str]) -> CheckResult:
    """Bonus: ensures errors are still captured server-side when display_errors=Off."""
    key = "log_errors"
    value = settings.get(key)

    if value is None or _is_on(value):
        return CheckResult(
            key=key, description="log_errors", status=Status.PASS,
            severity=Severity.INFO, current_value=value or "On (default)",
            expected="1 / On", recommendation="No action needed.",
            advisory_relevance=(
                "Server-side error logging stays available for detecting anomalous "
                "activity even with display_errors disabled."
            ),
        )

    return CheckResult(
        key=key, description="log_errors", status=Status.WARN,
        severity=Severity.MEDIUM, current_value=value, expected="1 / On",
        recommendation=f"Set `{key} = On` -- with display_errors correctly disabled, "
                        f"log_errors is your only visibility into application errors, "
                        f"including anomalies worth investigating during this advisory window.",
        advisory_relevance=(
            "With errors neither displayed nor logged, you lose visibility into "
            "exactly the kind of anomalous request handling this advisory concerns."
        ),
    )


ALL_CHECKS = [
    check_upload_progress,
    check_display_errors,
    check_fatal_error_backtraces,
    check_post_max_size,
    check_memory_limit,
    check_expose_php,
    check_log_errors,
]


def run_audit(settings: dict[str, str]) -> list[CheckResult]:
    return [check(settings) for check in ALL_CHECKS]
