"""Seal a scan's evidence so that anyone can check later that none of it was changed.

`promptproof seal RUN_DIR` packs every file of a finished run (reports, transcripts, the
egress trap's log, the teardown record) into one zip with a manifest, SEAL.json. The
manifest lists each file's SHA-256 and size and summarizes what the egress log shows.
Its own digest, the seal, is printed: send it to the customer separately, or put it in
the ticket, and the bundle can be checked against it at any time with
`promptproof check-seal BUNDLE --seal HEX`.

The egress trap's log is a hash chain (see egress_trap.py). The manifest records
whether the chain was intact and closed when the bundle was sealed, and `check-seal`
fails if it was broken: a bundle can be exactly what was sealed and still hold a log
that someone edited first.

What a seal proves, and what it does not: a matching seal shows the bundle is exactly
what existed when the seal was made and shared. It does not show who made it, or that
the evidence was complete and honest at that moment. A seal made by the customer's own
CI, from code they can read, is the strongest form of this. Signing by a hosted
service is a later step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from promptproof import __version__

MANIFEST = "SEAL.json"
EGRESS_LOG = "egress-trap.jsonl"
MAX_FILES = 10_000
MAX_TOTAL_BYTES = 2 * 1024**3


class SealError(Exception):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def seal_of(files: list[dict[str, Any]], egress: dict[str, Any] | None) -> str:
    """The seal: SHA-256 over the file list and the egress summary, in a fixed encoding."""
    return hashlib.sha256(_canonical({"files": files, "egress": egress})).hexdigest()


def _egress_summary(lines: bytes) -> dict[str, Any]:
    from promptproof.egress_trap import check_chain

    allowed: dict[str, int] = {}
    refused: dict[str, int] = {}
    unreadable = 0
    entries: list[dict[str, Any]] = []
    for raw in lines.splitlines():
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
            if not isinstance(entry, dict):
                raise TypeError("not an object")
            entries.append(entry)
            if "event" in entry:  # the trap's own start and stop lines
                continue
            target = str(entry["target"])
        except (ValueError, KeyError, TypeError):
            unreadable += 1
            continue
        bucket = allowed if entry.get("allowed") == "true" else refused
        bucket[target] = bucket.get(target, 0) + 1
    chain, closed = check_chain(entries) if not unreadable else ("broken: unreadable lines", False)
    return {
        "allowed": dict(sorted(allowed.items())),
        "refused": dict(sorted(refused.items())),
        "unreadable_lines": unreadable,
        # "intact": no line was changed, removed, added or reordered after it was written.
        # "closed": the log ends with the trap's stop line, so nothing was cut off the end.
        "chain": chain,
        "closed": closed,
    }


def _collect(run_dir: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_symlink():
            raise SealError(f"refusing to seal a link: {path}")
        if path.is_file():
            name = path.relative_to(run_dir).as_posix()
            if name == MANIFEST:
                raise SealError(f"{run_dir} already contains {MANIFEST}")
            found.append((name, path))
    if not found:
        raise SealError(f"no files in {run_dir}")
    if len(found) > MAX_FILES:
        raise SealError(f"more than {MAX_FILES} files in {run_dir}")
    return found


def seal(run_dir: Path, out: Path) -> str:
    """Write the bundle to `out` and return its seal."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise SealError(f"not a directory: {run_dir}")
    if out.resolve().is_relative_to(run_dir.resolve()):
        raise SealError("write the bundle outside the run directory, or it would seal itself")
    entries = _collect(run_dir)
    files: list[dict[str, Any]] = []
    egress: dict[str, Any] | None = None
    total = 0
    contents: list[tuple[str, bytes]] = []
    for name, path in entries:
        data = path.read_bytes()
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise SealError("the run directory is larger than 2 GB")
        files.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        contents.append((name, data))
        if name == EGRESS_LOG:
            egress = _egress_summary(data)
    value = seal_of(files, egress)
    manifest = {
        "format": "promptproof-seal/1",
        "tool_version": __version__,
        "sealed_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "files": files,
        "egress": egress,
        "seal": value,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in contents:
            bundle.writestr(name, data)
        bundle.writestr(MANIFEST, json.dumps(manifest, indent=2))
    return value


def check(bundle_path: Path, expected: str | None = None) -> dict[str, Any]:
    """Re-check a bundle without extracting it. Raises SealError on any mismatch."""
    try:
        bundle = zipfile.ZipFile(bundle_path)
    except (OSError, zipfile.BadZipFile) as error:
        raise SealError(f"not a readable bundle: {error}") from error
    with bundle:
        names = [info.filename for info in bundle.infolist() if not info.is_dir()]
        if len(names) != len(set(names)):
            raise SealError("the bundle holds two files with the same name")
        if MANIFEST not in names:
            raise SealError(f"no {MANIFEST} in the bundle")
        try:
            manifest = json.loads(bundle.read(MANIFEST))
            listed = manifest["files"]
            stated = manifest["seal"]
            paths = [item["path"] for item in listed]
        except (ValueError, KeyError, TypeError) as error:
            raise SealError(f"{MANIFEST} is malformed: {error}") from error
        for name in paths:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                raise SealError(f"unsafe path in the manifest: {name!r}")
        present = sorted(n for n in names if n != MANIFEST)
        if present != sorted(paths) or len(paths) != len(set(paths)):
            missing = sorted(set(paths) - set(present))
            extra = sorted(set(present) - set(paths))
            raise SealError(f"the bundle's files do not match the manifest (missing {missing}, extra {extra})")
        egress: dict[str, Any] | None = None
        for item in listed:
            data = bundle.read(item["path"])
            if hashlib.sha256(data).hexdigest() != item["sha256"] or len(data) != item["bytes"]:
                raise SealError(f"{item['path']} was changed after sealing")
            if item["path"] == EGRESS_LOG:
                egress = _egress_summary(data)
        if egress != manifest.get("egress"):
            raise SealError("the egress summary does not match the egress log")
        recomputed = seal_of(listed, egress)
        if recomputed != stated:
            raise SealError("the manifest was changed after sealing")
        if expected is not None and expected.strip().lower() != recomputed:
            raise SealError("the bundle is intact but its seal is not the one you were given")
        return manifest


def _seal_command(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    out = Path(args.out) if args.out else run_dir.with_name(run_dir.name + ".sealed.zip")
    try:
        value = seal(run_dir, out)
    except SealError as error:
        print(f"Not sealed: {error}")
        return 2
    print(f"Sealed {out}")
    print(f"Seal: {value}")
    print("Share the seal separately from the bundle. Anyone can then check the bundle with:")
    print(f"  promptproof check-seal {out} --seal {value}")
    return 0


def _check_command(args: argparse.Namespace) -> int:
    try:
        manifest = check(Path(args.bundle), args.seal)
    except SealError as error:
        print(f"FAILED: {error}")
        return 1
    print(f"Intact: {len(manifest['files'])} files, sealed {manifest['sealed_at']}, seal {manifest['seal']}")
    if args.seal is None:
        print("No --seal given: this shows the bundle is consistent, not that it is the one you were sent.")
    egress = manifest.get("egress")
    if egress is None:
        print("No egress log in this bundle.")
    else:
        allowed = ", ".join(f"{k} ({v})" for k, v in egress["allowed"].items()) or "none"
        refused = ", ".join(f"{k} ({v})" for k, v in egress["refused"].items()) or "none"
        print(f"Outbound traffic allowed: {allowed}")
        print(f"Outbound traffic refused: {refused}")
        chain = egress.get("chain", "absent")
        if chain == "intact" and egress.get("closed"):
            print("Outbound log: every line is chained to the one before, and it ends with the trap's stop line.")
            print("  (This shows no line was edited or dropped on its own. A log rewritten in full before sealing would")
            print("  also check; the seal shared when the run ended is what rules that out.)")
        elif chain == "intact":
            print("Outbound log: chained, BUT it has no stop line: it may have been cut short.")
        elif chain == "absent":
            print("Outbound log: not chained (an older version wrote it), so edits made before sealing would not show.")
        else:
            print(f"Outbound log: THE CHAIN IS {chain.upper()}. The log was changed after it was written.")
            print("FAILED: the bundle is what was sealed, but its outbound log cannot be relied on.")
            return 1
    return 0


def register(commands: argparse._SubParsersAction) -> None:
    sealing = commands.add_parser("seal", help="pack a finished run's evidence into a bundle anyone can check later")
    sealing.add_argument("run_dir", help="the directory holding the run's reports and logs")
    sealing.add_argument("--out", help="where to write the bundle (default: next to the directory)")
    sealing.set_defaults(handler=_seal_command)
    checking = commands.add_parser("check-seal", help="check that a sealed bundle was not changed")
    checking.add_argument("bundle")
    checking.add_argument("--seal", help="the seal you were given separately")
    checking.set_defaults(handler=_check_command)
