"""
version_check.py
-----------------
PASSIVE PHP version fingerprinting.

Everything in this module is read-only and non-adversarial:
  * It makes a single, ordinary GET request (no malformed input, no
    crafted multipart bodies, no boundary manipulation, no repeated
    requests designed to trigger engine state issues).
  * It only *reads* information the server already volunteers
    (HTTP response headers) or that the operator explicitly hands it
    (a phpinfo() dump, a composer.lock, a Server header string, etc).
  * It never attempts to trigger, probe for, or validate the behavior
    of the underlying CVEs. It answers exactly one question: "what
    version string is visible, and is that version string below the
    published patch threshold?"

This is intentionally the full extent of the "offensive-adjacent"
capability in php2shell-defender -- version comparison, not vulnerability
triggering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .version_db import VersionVerdict, evaluate_version

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


@dataclass
class FingerprintResult:
    source: str                      # "header" | "phpinfo" | "manual" | "none"
    raw_value: Optional[str]
    verdict: Optional[VersionVerdict]
    notes: list[str] = field(default_factory=list)


_PHPINFO_VERSION_RE = re.compile(
    r"PHP Version(?:</td>\s*<td[^>]*>|\s*=>\s*|\s*:\s*)(?:<[^>]+>\s*)*([\d]+\.[\d]+(?:\.[\d]+)?(?:-[A-Za-z0-9.]+)?)",
    re.IGNORECASE,
)
_SIMPLE_VERSION_RE = re.compile(r"PHP[/ ]([\d]+\.[\d]+(?:\.[\d]+)?(?:-[A-Za-z0-9.]+)?)")


def fingerprint_from_headers(headers: dict) -> FingerprintResult:
    """
    Inspect ordinary HTTP response headers for a version-bearing string.
    Looks at X-Powered-By first (most common), then falls back to Server.
    This performs no requests itself -- callers supply the headers dict,
    e.g. from `requests.get(url).headers`.
    """
    notes = []
    for header_name in ("X-Powered-By", "x-powered-by"):
        value = headers.get(header_name)
        if value and "php" in value.lower():
            match = _SIMPLE_VERSION_RE.search(value) or re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", value)
            if match:
                raw = match.group(1) if match.lastindex else match.group(0)
                return FingerprintResult(
                    source="header",
                    raw_value=raw,
                    verdict=evaluate_version(raw),
                    notes=[f"Detected via X-Powered-By: {value!r}"],
                )
            notes.append(f"X-Powered-By present ({value!r}) but no version number found in it.")

    server_value = headers.get("Server") or headers.get("server")
    if server_value and "php" in server_value.lower():
        match = _SIMPLE_VERSION_RE.search(server_value)
        if match:
            return FingerprintResult(
                source="header",
                raw_value=match.group(1),
                verdict=evaluate_version(match.group(1)),
                notes=[f"Detected via Server header: {server_value!r}"],
            )
        notes.append(f"Server header mentions PHP ({server_value!r}) but no version number found.")

    notes.append(
        "No PHP version string found in response headers. This commonly "
        "means `expose_php = Off` is already set (good hardening practice) "
        "-- use --phpinfo-file or --manual-version to fingerprint instead."
    )
    return FingerprintResult(source="none", raw_value=None, verdict=None, notes=notes)


def fingerprint_from_phpinfo_text(text: str) -> FingerprintResult:
    """
    Parse a phpinfo() HTML or plain-text dump the operator has already
    collected (e.g. saved from an authorized admin panel, or from
    `php -i`). This is text parsing only -- no requests are made here.
    """
    match = _PHPINFO_VERSION_RE.search(text)
    if not match:
        # Fallback: plain `php -i` / CLI output uses "PHP Version => 8.2.34"
        match = re.search(r"PHP Version\s*(?:=>|:)\s*([\d][\d.]*(?:-[A-Za-z0-9.]+)?)", text, re.IGNORECASE)

    if match:
        raw = match.group(1)
        return FingerprintResult(
            source="phpinfo",
            raw_value=raw,
            verdict=evaluate_version(raw),
            notes=["Parsed 'PHP Version' field from supplied phpinfo output."],
        )

    return FingerprintResult(
        source="none",
        raw_value=None,
        verdict=None,
        notes=["Could not locate a 'PHP Version' field in the supplied text."],
    )


def fingerprint_manual(version_string: str) -> FingerprintResult:
    """Operator directly supplies a known version string (e.g. from `php -v`)."""
    return FingerprintResult(
        source="manual",
        raw_value=version_string,
        verdict=evaluate_version(version_string),
        notes=["Version supplied directly by operator."],
    )


def fetch_headers(url: str, timeout: float = 10.0) -> dict:
    """
    Make a single, ordinary HTTP GET request and return response headers.

    This is a plain, unmodified request -- same as opening the URL in a
    browser. No custom headers, no malformed bodies, no multipart
    payloads, no repeated requests. It exists only to read whatever
    headers the server already sends to every normal visitor.
    """
    if requests is None:
        raise RuntimeError(
            "The 'requests' package is required for remote header fetching. "
            "Install it with: pip install requests"
        )
    resp = requests.get(url, timeout=timeout, allow_redirects=True)
    return dict(resp.headers)
