import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell_defender.ini_auditor import (
    parse_ini_text, parse_byte_size, run_audit, Status,
)

SAMPLE_VULNERABLE = """
; sample php.ini - intentionally insecure for testing
[PHP]
session.upload_progress.enabled = 1
display_errors = On
fatal_error_backtraces = 1
post_max_size = 0
memory_limit = -1
expose_php = On
log_errors = Off
"""

SAMPLE_HARDENED = """
[PHP]
session.upload_progress.enabled = 0
display_errors = Off
fatal_error_backtraces = 0
post_max_size = 16M
memory_limit = 256M
expose_php = Off
log_errors = On
"""


def test_parse_ini_text_basic():
    settings = parse_ini_text(SAMPLE_VULNERABLE)
    assert settings["session.upload_progress.enabled"] == "1"
    assert settings["display_errors"] == "On"
    assert settings["post_max_size"] == "0"
    assert settings["memory_limit"] == "-1"


def test_parse_ini_text_ignores_comments_and_sections():
    settings = parse_ini_text(SAMPLE_VULNERABLE)
    assert "[PHP]" not in settings
    assert all(not k.startswith(";") for k in settings)


def test_parse_byte_size():
    assert parse_byte_size("8M") == 8 * 1024 * 1024
    assert parse_byte_size("256K") == 256 * 1024
    assert parse_byte_size("2G") == 2 * 1024 * 1024 * 1024
    assert parse_byte_size("0") == 0
    assert parse_byte_size("-1") == -1
    assert parse_byte_size("garbage") is None


def test_audit_flags_vulnerable_config():
    settings = parse_ini_text(SAMPLE_VULNERABLE)
    results = run_audit(settings)
    by_key = {r.key: r for r in results}

    assert by_key["session.upload_progress.enabled"].status == Status.FAIL
    assert by_key["display_errors"].status == Status.FAIL
    assert by_key["post_max_size"].status == Status.FAIL
    assert by_key["memory_limit"].status == Status.FAIL
    assert by_key["expose_php"].status == Status.WARN
    assert by_key["log_errors"].status == Status.WARN


def test_audit_passes_hardened_config():
    settings = parse_ini_text(SAMPLE_HARDENED)
    results = run_audit(settings)
    by_key = {r.key: r for r in results}

    assert by_key["session.upload_progress.enabled"].status == Status.PASS
    assert by_key["display_errors"].status == Status.PASS
    assert by_key["post_max_size"].status == Status.PASS
    assert by_key["memory_limit"].status == Status.PASS
    assert by_key["expose_php"].status == Status.PASS
    assert by_key["log_errors"].status == Status.PASS


def test_audit_unknown_when_missing():
    results = run_audit({})
    statuses = {r.key: r.status for r in results}
    assert statuses["session.upload_progress.enabled"] == Status.UNKNOWN


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok: {name}")
    print("all ini_auditor tests passed")
