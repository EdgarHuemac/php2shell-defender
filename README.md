# php2shell-defender

> **Emergency Incident Response:** Built in a frantic rush immediately following yesterday's **php2shell** advisory drop (CVE-2026-109618, CVE-2026-109619). Designed to instantly audit configurations and verify versions during the critical window before official patches roll out.

A **purely defensive** CLI companion. This is **not an exploit or probing logic**, but just safe configuration auditing and passive version checks.

### What it does

1. Parses `php.ini` against interim hardening recommendations (`session.upload_progress.enabled`, `display_errors`, `post_max_size`, `memory_limit`, etc.).
2. Reads version strings via headers, phpinfo dumps, or a single ordinary `GET` request (no malformed payloads or engine state probing).

### Install

```bash
pip install -r requirements.txt
pip install -e .
```
### Quick Usage


```python
# audit a local php.ini and manual version
python3 -m php2shell_defender.cli --ini-file /etc/php/8.2/fpm/php.ini --manual-version 8.2.30

# passively check a live host
python3 -m php2shell_defender.cli --url [https://example.com/](https://example.com/)

# generate a ready-to-apply fix snippet
python3 -m php2shell_defender.cli --ini-file /etc/php/8.2/fpm/php.ini --emit-ini-snippet /tmp/php2shell-fix.ini

# fleet-wide triage (sorted worst-risk-first)
python3 -m php2shell_defender.fleet --targets-file samples/targets.txt.example
```
### Exit codes
Maybe useful for CI/cron gating, idk:

| Code | Meaning |
|---|---|
| 0 | LOW risk - config passes, version patched (or not checked)   :D |
| 1 | MEDIUM risk - some hardening gaps   :O |
| 2 | HIGH/CRITICAL - vulnerable version and/or missing high-severity mitigations   :'( |

### try it on the bundled samples

```bash
# deliberately insecure config -> should exit 2 (CRITICAL)
python3 -m php2shell_defender.cli \
  --ini-file samples/php.ini.vulnerable-example --manual-version 8.2.30

# hardened config -> should exit 0 (LOW)
python3 -m php2shell_defender.cli \
  --ini-file samples/php.ini.hardened-example --manual-version 8.3.36
```

This is not a scanner that triggers or validates the vulnerabilities. Its sole job is to shrink your exposure window through immediate configuration hardening and visibility. Subject to updates, maybe.
