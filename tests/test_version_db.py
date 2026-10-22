import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from php2shell_defender.version_db import evaluate_version, parse_version


def test_parse_version_basic():
    assert parse_version("8.2.34") == (8, 2, 34)
    assert parse_version("PHP/8.3.36") == (8, 3, 36)
    assert parse_version("8.4.27-dev") == (8, 4, 27)
    assert parse_version("8.5") == (8, 5, 0)
    assert parse_version("not a version") is None
    assert parse_version("") is None


def test_vulnerable_below_threshold():
    v = evaluate_version("8.2.34")
    assert v.status == "vulnerable"
    assert v.patched_target == (8, 2, 35)


def test_patched_at_threshold():
    v = evaluate_version("8.2.35")
    assert v.status == "patched"


def test_patched_above_threshold():
    v = evaluate_version("8.3.40")
    assert v.status == "patched"


def test_eol_branch():
    v = evaluate_version("7.4.33")
    assert v.status == "eol"


def test_unknown_branch():
    v = evaluate_version("9.9.0")
    assert v.status == "unknown"


def test_unparseable():
    v = evaluate_version("garbage")
    assert v.status == "unknown"
    assert v.parsed is None


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok: {name}")
    print("all version_db tests passed")
