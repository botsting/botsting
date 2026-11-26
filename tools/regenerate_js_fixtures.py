"""Regenerate the Python-signed values the JavaScript tests compare bytes with.

    python tools/regenerate_js_fixtures.py            # rewrite js/harness/test/firstscan.test.js if needed
    python tools/regenerate_js_fixtures.py --check    # exit 1 if they are out of date; change nothing

The JavaScript harness must produce, byte for byte, what the Python harness produces.
Its tests hold four values made by the Python harness: two session tokens and two
signed records. They change whenever the wire format does, and when the project is
renamed (the name is part of what is signed). This script is the one place that knows
how each was made.

The harness is loaded from its file, whatever the package is called at the time.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "js" / "harness" / "test" / "firstscan.test.js"
KEY = "k" * 40


def load_harness():
    (path,) = sorted(ROOT.glob("src/*/harness.py"))
    spec = importlib.util.spec_from_file_location("harness_for_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up while it is being defined
    spec.loader.exec_module(module)
    return module


def values() -> dict[str, str]:
    pp = load_harness()
    fixed = {"lifetime_seconds": 300.0, "now": 1000000.0, "nonce": "n1"}
    control = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE-7"}, {}, control={"admin_code": "open sesame"}, discover=True, **fixed)
    plain = pp.make_session_token(KEY, "s1", {"admin_code": "FAKE-7"}, {}, **fixed)
    pp._marked_tools.clear()
    pp._marked_tools.update({"send_email": "", "issue_refund": "a refund of 50 on order A-1001"})
    pp._read_outside.clear()
    pp._read_outside.add("held_at_start")
    pp._content_outside.clear()
    session = pp._Session(sid="s1", fixtures={}, content={}, key=KEY, nonce="n1")
    session.read.append("staff_code")
    return {
        "PYTHON_CONTROL_TOKEN": control,
        "PYTHON_PLAIN_TOKEN": plain,
        "PYTHON_READY_RECORD": session.header_value(tools=True),
        "PYTHON_PLAIN_RECORD": session.header_value(),
    }


def rewritten(text: str) -> str:
    for name, value in values().items():
        text, count = re.subn(rf'(const {name} =\n  ")[^"]+(";)', lambda m, v=value: m.group(1) + v + m.group(2), text)
        if count != 1:
            raise SystemExit(f"{FIXTURES.name}: expected one `const {name} =` followed by a quoted value, found {count}")
    return text


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    before = FIXTURES.read_bytes().decode("utf-8")
    after = rewritten(before)
    if after == before:
        print("The JavaScript test fixtures are up to date.")
        return 0
    if check:
        print("The JavaScript test fixtures are out of date. Run: python tools/regenerate_js_fixtures.py")
        return 1
    FIXTURES.write_bytes(after.encode("utf-8"))
    print(f"Rewrote the signed values in {FIXTURES.relative_to(ROOT)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
