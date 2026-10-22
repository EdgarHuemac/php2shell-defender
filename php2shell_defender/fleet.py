"""
fleet.py
---------
Optional fleet-wide wrapper: run the same passive version check + (optionally)
a shared ini audit across a list of hosts, and print a single sorted summary
table so you can triage "which of our N servers needs attention first"
during the PoC-to-patch window.

Input is a plain text file, one target per line:
    https://app1.internal.example.com
    https://app2.internal.example.com
    # comments and blank lines are ignored
    https://app3.internal.example.com

Each line is treated exactly like a single `--url` run: one ordinary GET
request, headers inspected passively. No config auditing is attempted per
host unless you separately provide a shared --ini-file (useful when a
fleet shares one php.ini via config management).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .ini_auditor import run_audit, load_ini_file
from .version_check import fingerprint_from_headers, fetch_headers
from .report import compute_risk_score, VERDICT_COLORS, RESET


def read_targets(path: str) -> list[str]:
    targets = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def scan_one(url: str, shared_settings: dict, timeout: float, use_color: bool) -> dict:
    try:
        headers = fetch_headers(url, timeout=timeout)
        fp = fingerprint_from_headers(headers)
        verdict = fp.verdict
        error = None
    except Exception as exc:
        verdict = None
        error = str(exc)

    results = run_audit(shared_settings) if shared_settings else []
    risk = compute_risk_score(results, verdict)

    return {
        "url": url,
        "verdict": verdict,
        "risk": risk,
        "error": error,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-defender-fleet",
        description="Run php2shell-defender's passive version check across many hosts.",
    )
    parser.add_argument("--targets-file", required=True, metavar="PATH",
                         help="Text file with one URL per line")
    parser.add_argument("--ini-file", metavar="PATH",
                         help="Optional shared php.ini to factor into each host's risk score "
                              "(use when the fleet shares one config)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-host request timeout (s)")
    parser.add_argument("--no-color", action="store_true")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    targets = read_targets(args.targets_file)
    if not targets:
        print("No targets found in targets file.", file=sys.stderr)
        return 1

    shared_settings = load_ini_file(args.ini_file) if args.ini_file else {}

    rows = []
    for url in targets:
        print(f"scanning {url} ...", file=sys.stderr)
        rows.append(scan_one(url, shared_settings, args.timeout, not args.no_color))

    rows.sort(key=lambda r: r["risk"]["score"], reverse=True)

    use_color = not args.no_color
    print()
    print(f"{'STATUS':<12}{'RISK':<10}{'TARGET'}")
    print("-" * 72)
    for row in rows:
        if row["error"]:
            status = "ERROR"
            risk_str = "-"
        elif row["verdict"] is None:
            status = "UNKNOWN"
            risk_str = str(row["risk"]["score"])
        else:
            status = row["verdict"].status.upper()
            risk_str = f"{row['risk']['score']} ({row['risk']['band']})"

        color = VERDICT_COLORS.get(status.lower(), "") if use_color else ""
        reset = RESET if use_color else ""
        print(f"{color}{status:<12}{reset}{risk_str:<10}{row['url']}")
        if row["error"]:
            print(f"             -> {row['error']}")

    worst = rows[0]["risk"]["band"] if rows else "LOW"
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 2}.get(worst, 0)


if __name__ == "__main__":
    sys.exit(main())
