"""Rename the project in one pass, once a name is chosen.

    python tools/rename_project.py BotPentest            # show what would change
    python tools/rename_project.py BotPentest --apply    # change it

The argument is the name as it is written in prose ("BotPentest"). From it:

    in prose, headers, titles     BotPentest      (was the capitalised working name)
    package, command, files       botpentest      (was the lower-case working name)
    environment variables         BOTPENTEST      (was the upper-case working name)

It changes every file git tracks: file contents, and file and folder names. That covers
the Python package and its command, the environment variables, the HTTP headers and
well-known paths the harness and scanner agree on, the JavaScript package, the GitHub
Action, the assistant plug-in and the documents. It leaves alone what git ignores (notes,
research, local runs, reports), the lock file (regenerate it: `uv lock`), and this script.

After `--apply`, three things in order:

    uv lock && uv sync                                  # the lock file and the installed command
    python tools/regenerate_js_fixtures.py              # signed records the JavaScript tests compare bytes with
    python -m pytest -q && node --test "js/harness/test/*.test.js"

The signed records change because the old name is part of what is signed. A bot and a
scanner must therefore be on the same side of the rename: nothing is released yet, so
there is no deployed bot to keep working.

It refuses to run on a tree with uncommitted changes, so the rename is one clean commit
and `git checkout .` undoes a mistake. It never touches anything outside the repository.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

OLD = "prompt" + "proof"  # written in two parts so that this file does not rename itself
SKIP = {"uv.lock", "tools/rename_project.py"}
NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{2,29}")


def tracked(root: Path) -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [name for name in out.decode("utf-8").split("\0") if name and name not in SKIP]


def plan(root: Path, display: str) -> tuple[list[tuple[str, int]], list[tuple[str, str]], list[str]]:
    """What would change: (file, replacements) for contents, (old path, new path) for names, and
    files that could not be read as text and are left alone."""
    lower, upper = display.lower(), display.upper()
    pairs = ((OLD.upper(), upper), (OLD.capitalize(), display), (OLD, lower))
    contents: list[tuple[str, int]] = []
    moves: list[tuple[str, str]] = []
    skipped: list[str] = []
    for name in tracked(root):
        path = root / name
        try:
            text = path.read_bytes().decode("utf-8")
        except (UnicodeDecodeError, OSError):
            skipped.append(name)
            text = None
        if text is not None:
            count = sum(text.count(old) for old, _ in pairs)
            left = len(re.findall(OLD, text, flags=re.IGNORECASE)) - count
            if left:
                raise SystemExit(f"{name}: {left} spelling(s) of the old name in a case this script does not know; fix by hand first")
            if count:
                contents.append((name, count))
        if OLD in name.lower():
            moves.append((name, re.sub(OLD, lower, name, flags=re.IGNORECASE)))
    return contents, moves, skipped


def apply(root: Path, display: str, contents: list[tuple[str, int]], moves: list[tuple[str, str]]) -> None:
    lower, upper = display.lower(), display.upper()
    for name, _ in contents:
        path = root / name
        data = path.read_bytes().decode("utf-8")  # bytes in and out: line endings are kept as they are
        data = data.replace(OLD.upper(), upper).replace(OLD.capitalize(), display).replace(OLD, lower)
        path.write_bytes(data.encode("utf-8"))
    for old, new in moves:
        target = root / new
        target.parent.mkdir(parents=True, exist_ok=True)
        (root / old).rename(target)
    # Folders left empty by the moves (the old package folder, for one). Only empty ones go.
    for old, _ in moves:
        parent = (root / old).parent
        while parent != root and parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rename the project in one pass.")
    parser.add_argument("name", help='the new name as written in prose, for example "BotPentest"')
    parser.add_argument("--apply", action="store_true", help="make the changes (without it, only show them)")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]), help="the repository (default: this one)")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not NAME.fullmatch(args.name):
        print("error: the name must be 3 to 30 letters and digits, starting with a letter, with no spaces or hyphens")
        return 2
    if args.name.lower() == OLD:
        print("error: that is the current name")
        return 2
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=root, check=True, capture_output=True).stdout.strip()
    if dirty and args.apply:
        print("error: there are uncommitted changes; commit or stash them first, so the rename is one clean commit")
        return 2
    contents, moves, skipped = plan(root, args.name)
    total = sum(count for _, count in contents)
    print(f"{args.name} / {args.name.lower()} / {args.name.upper()}")
    print(f"{total} replacement(s) in {len(contents)} file(s); {len(moves)} file(s) moved.")
    for name in skipped:
        print(f"  left alone (not text): {name}")
    if not args.apply:
        for name, count in sorted(contents, key=lambda item: -item[1])[:15]:
            print(f"  {count:>4}  {name}")
        print("Nothing was changed. Add --apply to make the changes.")
        return 0
    apply(root, args.name, contents, moves)
    print("Done. Next: uv lock && uv sync; python tools/regenerate_js_fixtures.py; then run both test suites.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
