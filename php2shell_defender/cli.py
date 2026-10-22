"""
cli.py
-------
php2shell-defender: a purely defensive CLI companion to the PHP2Shell
advisory.

It does two things, and only two things:
  1. Audits php.ini-style configuration against recommended interim
     mitigations (upload-progress, display_errors, memory ceilings, etc).
  2. Passively fingerprints a PHP version (from headers, a phpinfo dump,
     or a value you already know) and compares it against the published
     patched-version table.

It never sends crafted, malformed, or adversarial requests, and never
attempts to trigger the behavior described in the advisory. See README.md
for the project's scope statement.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .ini_auditor import run_audit, parse_ini_text, load_ini_file, parse_kv_pairs
from .version_check import (
    fingerprint_from_headers,
    fingerprint_from_phpinfo_text,
    fingerprint_manual,
    fetch_headers,
)
from .version_db import VersionVerdict
from . import report as report_mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-defender",
        description=(
            "Defensive hardening & patch-status auditor for the PHP2Shell "
            "advisory. Config auditing + passive version fingerprinting only "
            "-- no exploit or probing logic."
        ),
    )
    parser.add_argument(
        "--format", choices=["text", "json", "markdown"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color in text output",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Write report to FILE instead of stdout",
    )
    parser.add_argument(
        "--emit-ini-snippet", metavar="FILE",
        help="Also write a remediation php.ini snippet to FILE",
    )

    # --- ini source (pick one) ---
    ini_group = parser.add_argument_group("php.ini source")
    ini_src = ini_group.add_mutually_exclusive_group()
    ini_src.add_argument("--ini-file", metavar="PATH", help="Path to a php.ini file to audit")
    ini_src.add_argument("--ini-text", metavar="PATH",
                          help="Path to a text file containing php.ini-style lines "
                               "(e.g. output of `php -i`)")
    ini_group.add_argument(
        "--set", action="append", default=[], metavar="KEY=VALUE",
        help="Supply/override a single directive manually. Repeatable. "
             "Example: --set session.upload_progress.enabled=1",
    )

    # --- version source (pick one) ---
    ver_group = parser.add_argument_group("version source")
    ver_src = ver_group.add_mutually_exclusive_group()
    ver_src.add_argument("--url", metavar="URL",
                          help="Fetch a single ordinary GET request and inspect its "
                               "response headers for a PHP version banner")
    ver_src.add_argument("--phpinfo-file", metavar="PATH",
                          help="Path to a saved phpinfo() HTML/text dump or `php -i` output")
    ver_src.add_argument("--manual-version", metavar="X.Y.Z",
                          help="Directly supply a known PHP version string, e.g. 8.2.30")

    parser.add_argument(
        "--target-label", metavar="NAME",
        help="Human-readable label for this scan target, used in the report header "
             "(defaults to the --url / --ini-file value or 'local')",
    )

    return parser


def _gather_settings(args) -> dict[str, str]:
    settings: dict[str, str] = {}

    if args.ini_file:
        settings.update(load_ini_file(args.ini_file))
    elif args.ini_text:
        text = Path(args.ini_text).read_text(encoding="utf-8", errors="replace")
        settings.update(parse_ini_text(text))

    # --set overrides always apply last, so operators can patch in a
    # single directive even when auditing a file.
    settings.update(parse_kv_pairs(args.set))

    return settings


def _gather_verdict(args) -> Optional[VersionVerdict]:
    if args.url:
        headers = fetch_headers(args.url)
        result = fingerprint_from_headers(headers)
        for note in result.notes:
            print(f"[version] {note}", file=sys.stderr)
        return result.verdict

    if args.phpinfo_file:
        text = Path(args.phpinfo_file).read_text(encoding="utf-8", errors="replace")
        result = fingerprint_from_phpinfo_text(text)
        for note in result.notes:
            print(f"[version] {note}", file=sys.stderr)
        return result.verdict

    if args.manual_version:
        result = fingerprint_manual(args.manual_version)
        return result.verdict

    return None


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not any([args.ini_file, args.ini_text, args.set, args.url, args.phpinfo_file, args.manual_version]):
        parser.error(
            "Nothing to audit -- supply at least one of: "
            "--ini-file / --ini-text / --set (config audit) or "
            "--url / --phpinfo-file / --manual-version (version check)."
        )

    settings = _gather_settings(args)
    results = run_audit(settings)

    try:
        verdict = _gather_verdict(args)
    except Exception as exc:  # network errors, missing deps, bad files, etc.
        print(f"error: could not determine version: {exc}", file=sys.stderr)
        verdict = None

    target = args.target_label or args.url or args.ini_file or args.ini_text or "local configuration"

    if args.format == "json":
        output = report_mod.render_json(results, verdict, target)
    elif args.format == "markdown":
        output = report_mod.render_markdown(results, verdict, target)
    else:
        output = report_mod.render_text(results, verdict, target, use_color=not args.no_color and args.output is None)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)

    if args.emit_ini_snippet:
        snippet = report_mod.render_ini_snippet(results)
        Path(args.emit_ini_snippet).write_text(snippet, encoding="utf-8")
        print(f"Remediation snippet written to {args.emit_ini_snippet}")

    risk = report_mod.compute_risk_score(results, verdict)
    # Exit code reflects posture: 0 = clean, 1 = needs attention, 2 = critical/vulnerable.
    if risk["band"] in ("HIGH", "CRITICAL"):
        return 2
    if risk["band"] == "MEDIUM":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
