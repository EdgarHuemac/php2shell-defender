"""
version_db.py
--------------
Central registry of "patched / fixed" PHP versions per branch.

This is the single source of truth the rest of php2shell-defender uses to
decide whether a detected PHP version is vulnerable to the issues tracked
under the PHP2Shell advisory. Keeping it in one small, obviously-editable
file means you can update it the moment a vendor revises an advisory
without touching any detection logic.

Advisory baseline (as supplied by the user):
    PHP 8.2 series -> fixed in 8.2.35
    PHP 8.3 series -> fixed in 8.3.36
    PHP 8.4 series -> fixed in 8.4.27
    PHP 8.5 series -> fixed in 8.5.12

Branches not listed here are reported as UNKNOWN rather than silently
assumed safe or vulnerable -- that is a deliberate fail-safe default for
a security tool: we never want a version we don't recognize to be
reported as "patched".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

Version = Tuple[int, int, int]

# branch (major, minor) -> minimum patched (major, minor, patch)
PATCHED_VERSIONS: dict[Tuple[int, int], Version] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Branches that are fully EOL / unsupported regardless of patch level.
# Any version in these branches is flagged CRITICAL ("no fix will ever
# arrive") rather than compared against a patched threshold.
EOL_BRANCHES = {
    (5, 6), (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0), (8, 1),
}

ADVISORY_REFERENCE = {
    "cve_ids": ["CVE-2026-109618", "CVE-2026-109619"],
    "note": (
        "CVE identifiers as supplied by the requesting team. This tool does "
        "not independently verify CVE metadata against NVD/MITRE -- treat "
        "the IDs as a label for this advisory, and confirm against your "
        "vendor's official bulletin before using them in compliance "
        "reporting."
    ),
}


@dataclass
class VersionVerdict:
    raw_version: str
    parsed: Optional[Version]
    branch: Optional[Tuple[int, int]]
    status: str          # "patched" | "vulnerable" | "eol" | "unknown"
    patched_target: Optional[Version]
    detail: str

    @property
    def branch_str(self) -> Optional[str]:
        return f"{self.branch[0]}.{self.branch[1]}" if self.branch else None

    @property
    def patched_target_str(self) -> Optional[str]:
        if not self.patched_target:
            return None
        return ".".join(str(p) for p in self.patched_target)


def parse_version(raw: str) -> Optional[Version]:
    """
    Parse a loosely-formatted PHP version string into (major, minor, patch).

    Handles things like:
        "8.2.34"
        "8.2.34-dev"
        "8.3.36RC1"
        "PHP/8.2.34"
        "8.2"            -> (8, 2, 0)
    Returns None if nothing resembling a PHP version can be found.
    """
    import re

    if not raw:
        return None

    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", raw)
    if not match:
        return None

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3)) if match.group(3) else 0
    return (major, minor, patch)


def evaluate_version(raw_version: str) -> VersionVerdict:
    """
    Compare a raw version string against the patched-version database and
    return a structured verdict. This function contains no network or
    request-crafting logic -- it is pure comparison against a static table.
    """
    parsed = parse_version(raw_version)
    if parsed is None:
        return VersionVerdict(
            raw_version=raw_version,
            parsed=None,
            branch=None,
            status="unknown",
            patched_target=None,
            detail="Could not parse a PHP version number from the supplied string.",
        )

    branch = (parsed[0], parsed[1])

    if branch in EOL_BRANCHES:
        return VersionVerdict(
            raw_version=raw_version,
            parsed=parsed,
            branch=branch,
            status="eol",
            patched_target=None,
            detail=(
                f"PHP {branch[0]}.{branch[1]} is end-of-life and will not "
                "receive a security fix for this advisory. Upgrade to a "
                "supported branch (8.2+) as the only remediation."
            ),
        )

    if branch not in PATCHED_VERSIONS:
        return VersionVerdict(
            raw_version=raw_version,
            parsed=parsed,
            branch=branch,
            status="unknown",
            patched_target=None,
            detail=(
                f"PHP {branch[0]}.{branch[1]} is not in the known advisory "
                "table. It may be newer than this tool's database, or "
                "outside the branches covered by the advisory -- verify "
                "manually against the vendor bulletin."
            ),
        )

    target = PATCHED_VERSIONS[branch]
    if parsed >= target:
        return VersionVerdict(
            raw_version=raw_version,
            parsed=parsed,
            branch=branch,
            status="patched",
            patched_target=target,
            detail=f"Version meets or exceeds the patched threshold {'.'.join(map(str, target))}.",
        )

    return VersionVerdict(
        raw_version=raw_version,
        parsed=parsed,
        branch=branch,
        status="vulnerable",
        patched_target=target,
        detail=(
            f"Version is below the patched threshold "
            f"{'.'.join(map(str, target))} for the {branch[0]}.{branch[1]} branch."
        ),
    )
