import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell_defender.version_check import (
    fingerprint_from_headers, fingerprint_from_phpinfo_text, fingerprint_manual,
)


def test_fingerprint_from_headers_x_powered_by():
    result = fingerprint_from_headers({"X-Powered-By": "PHP/8.2.34"})
    assert result.source == "header"
    assert result.verdict.status == "vulnerable"


def test_fingerprint_from_headers_server():
    result = fingerprint_from_headers({"Server": "Apache/2.4.58 (Ubuntu) PHP/8.3.36"})
    assert result.source == "header"
    assert result.verdict.status == "patched"


def test_fingerprint_from_headers_none_found():
    result = fingerprint_from_headers({"Server": "nginx/1.25.3"})
    assert result.source == "none"
    assert result.verdict is None


def test_fingerprint_from_phpinfo_cli_style():
    text = "phpinfo()\nPHP Version => 8.4.26\nSystem => Linux\n"
    result = fingerprint_from_phpinfo_text(text)
    assert result.verdict.status == "vulnerable"
    assert result.verdict.patched_target == (8, 4, 27)


def test_fingerprint_from_phpinfo_html_style():
    text = "<tr><td>PHP Version</td><td>8.5.12</td></tr>"
    result = fingerprint_from_phpinfo_text(text)
    assert result.verdict.status == "patched"


def test_fingerprint_manual():
    result = fingerprint_manual("8.1.9")
    assert result.verdict.status == "eol"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok: {name}")
    print("all version_check tests passed")
