"""`kritalon doctor`: check a bot's setup step by step and say what to do next.

    kritalon doctor --target http:staging

It walks the same gates a scan does, in order, and stops explaining at the first one
that is not passed, with the command or change that fixes it:

    1. the description     is the target described, and does the description parse?
    2. what it protects    does it name at least one secret or tool rule, and a normal-use check?
    3. credentials         are the environment variables its headers use set?
    4. the harness key     (drop-in harness only) is the key set here?
    5. authorization       has a person authorized this address, and does it cover the tools?
       deployment settings (with --env-file) does the deployment's configuration hold production keys?
    6. proof of control    (across a network) does the address still serve its token?
    7. the harness         (drop-in harness only) does the bot confirm test mode?
    8. a legitimate run    can each secret be fetched by someone allowed it, and does normal use work?

Nothing hostile is sent. Steps 6 to 8 talk to the bot, so they run only after step 5:
the same rule as a scan. Step 8 sends only the description's own control prompts and
normal-use prompts, as the users allowed to send them; it is the check a scan makes
before its first attack. `--offline` stops after step 5.

Exit codes: 0 ready to scan, 2 something to fix.
"""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import Callable
from typing import Any

from kritalon.exits import EXIT_FAILED, EXIT_OK

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Header names that carry a credential. A header that only says who the test user is (X-User: bob) is not one.
_SECRET_HEADER = re.compile(r"authorization|cookie|token|secret|password|api[-_]?key|(^|[-_])key($|[-_])|signature", re.IGNORECASE)


class _Report:
    def __init__(self, out: Callable[[str], None]) -> None:
        self.out = out
        self.failed = False

    def ok(self, step: str, detail: str) -> None:
        self.out(f"  ok    {step}: {detail}")

    def note(self, step: str, detail: str) -> None:
        self.out(f"  note  {step}: {detail}")

    def fix(self, step: str, problem: str, how: str) -> None:
        self.failed = True
        self.out(f"  FIX   {step}: {problem}")
        for line in how.splitlines():
            self.out(f"          {line}")


def diagnose(spec: str, offline: bool = False, out: Callable[[str], None] = print, env_files: tuple[str, ...] = ()) -> bool:
    """Run the checks, printing through `out`. Returns True when the target is ready to scan.

    `env_files` are exports of the deployment's own settings (never this machine's): they are checked
    for production keys, by name and known prefix only."""
    from kritalon.core.authorization import (
        AuthorizationError,
        confirm_proof,
        require_authorized,
    )
    from kritalon.core.runner import Meter, preflight
    from kritalon.targets.base import (
        TargetError,
        UnsafeTargetError,
        require_contained_tools,
    )
    from kritalon.targets.registry import SpecError, build_target

    report = _Report(out)
    out(f"Checking {spec}")

    # 1. The description.
    try:
        target: Any = build_target(spec)
    except SpecError as error:
        report.fix(
            "description", str(error), "Describe the bot in kritalon.targets.json. `kritalon guide` shows the format."
        )
        return False
    config = getattr(target, "config", None)
    if config is None:
        report.ok("description", "a built-in practice bot; it runs inside this process and needs no setup")
        return True
    report.ok("description", f"{config.name} at {config.origin}")

    # 2. What it protects.
    if not config.slots and not config.tool_rules and not config.injection_points:
        report.fix(
            "what it protects",
            "the description names no secret slot, tool rule or injection point, so a scan has nothing to prove",
            'Add at least one entry under "slots" or "tool_rules".',
        )
    else:
        report.ok(
            "what it protects",
            f"{len(config.slots)} secret slot(s), {len(config.tool_rules)} tool rule(s), "
            f"{len(config.injection_points)} injection point(s)",
        )
    if not config.task_checks:
        report.note(
            "normal use", 'no "task_checks": add one ordinary request, so a bot that refuses everything is not called safe'
        )

    # 3. Credentials.
    wanted = sorted({name for p in config.principals.values() for value in p.headers.values() for name in _ENV.findall(value)})
    missing = [name for name in wanted if not os.environ.get(name)]
    if missing:
        report.fix(
            "credentials", f"not set in this environment: {', '.join(missing)}", "Set each to the test account's credential."
        )
    elif wanted:
        report.ok("credentials", f"{len(wanted)} environment variable(s) set")
    written = [
        n
        for n, p in config.principals.items()
        if any(v and "${" not in v and _SECRET_HEADER.search(k) for k, v in p.headers.items())
    ]
    if written:
        report.note("credentials", f"a credential for {', '.join(written)} is written out in the file; use ${{NAME}} to keep it out")

    # 4. The harness key.
    sdk = config.harness == "sdk"
    if sdk:
        try:
            target.harness_key()
            report.ok("harness key", f"{config.harness_key_env} is set here")
        except TargetError as error:
            report.fix(
                "harness key",
                str(error),
                f"Run `kritalon harness-key`, then set {config.harness_key_env} here and on the deployment under test.",
            )

    # 5. Authorization.
    tools = sorted({r.tool for r in config.tool_rules} | {t for p in config.injection_points for t in p.forbidden_tools})
    flags = "".join(f" --tool {tool}" for tool in tools) + "".join(f" --live-tool {tool}" for tool in config.live_actions)
    command = f'kritalon authorize {config.origin} --by "YOUR NAME" --scope "what may be tested" --environment staging{flags}'
    proof = None
    try:
        proof = require_authorized(target)
        require_contained_tools(target)
        record = target.authorization
        report.ok(
            "authorization",
            f"by {record.authorized_by}, {record.environment}, until {record.expires_at}"
            + (f"; may carry out for real: {', '.join(record.live_tools)}" if record.live_tools else ""),
        )
    except (AuthorizationError, UnsafeTargetError) as error:
        how = "A person who may allow this test runs:\n" + command
        if "has not been verified" in str(error):
            how = (
                f"Serve the token (see `kritalon authorize --list`), then run:\nkritalon authorize --verify {config.origin}"
            )
        report.fix("authorization", str(error), how)
        out("  Stopped here: nothing is sent to a bot without an authorization.")
        return False
    # The deployment's own settings, if the owner exported them: no production keys on a test deployment.
    if env_files:
        from kritalon.sterility import EnvFileError, check, read_env_file

        try:
            variables: dict[str, str] = {}
            for path in env_files:
                variables.update(read_env_file(path))
        except EnvFileError as error:
            report.fix("deployment settings", str(error), "Give an env file of KEY=value lines exported from the deployment.")
        else:
            sterile = check(variables)
            live = [f for f in sterile.findings if f.severity == "live" and not f.allowed]
            if not live:
                report.ok(
                    "deployment settings",
                    f"{sterile.checked_count} variable(s) checked, no production signal; "
                    f"{sterile.unknown_count} could not be told apart and are worth a look",
                )
            elif target.authorization.environment == "production":
                report.note(
                    "deployment settings",
                    f"{len(live)} production signal(s), as expected for a test of the real system: "
                    + ", ".join(f.name for f in live),
                )
            else:
                report.fix(
                    "deployment settings",
                    f"this {target.authorization.environment} deployment holds production settings: "
                    + ", ".join(f"{f.name} ({f.reason})" for f in live),
                    "Replace each with a test value before scanning, or a test could reach real systems.\n"
                    "Details: kritalon sterile-check --env-file <file>",
                )
    if report.failed:
        out("  Stopped here: fix the points above, then run this again.")
        return False
    if offline:
        out("  Offline checks passed. Run without --offline to check the bot itself.")
        return True

    async def online() -> None:
        # 6. Proof of control.
        if proof is not None:
            try:
                await confirm_proof(proof, fresh=True)
                report.ok("proof of control", f"{config.origin} serves its token")
            except AuthorizationError as error:
                report.fix(
                    "proof of control",
                    str(error),
                    "Serve the token line as plain text at /.well-known/kritalon-challenge.txt. With the drop-in\n"
                    "harness, set KRITALON_CHALLENGE on the deployment to that line and it is served for you.",
                )
                return
        else:
            report.ok("proof of control", "not needed for a bot on this machine")
        # 7. The harness.
        if sdk:
            try:
                await target.reset({})
                report.ok("harness", "the bot confirmed test mode for a signed session")
            except TargetError as error:
                report.fix(
                    "harness",
                    str(error),
                    f"Check that the app is wrapped (`app = pp.wrap(app)`), that it is deployed, and that\n"
                    f"{config.harness_key_env} on the deployment is the same key as here.",
                )
                return
        # 8. A legitimate run: what a scan checks before its first attack.
        checks = await preflight(target, Meter())
        for status in checks.slots:
            if status.state == "reachable":
                report.ok(f"legitimate use of {status.slot_id}", "works by its allowed route")
            else:
                report.fix(
                    f"legitimate use of {status.slot_id}",
                    f"{status.state}: {status.detail}",
                    "The control prompt must make the bot give this secret, or carry out this tool, for the user allowed it.\n"
                    "Check where pp.planted(...) is placed, that the tool carries @pp.action, and the control_prompt's wording.",
                )
        for task in checks.tasks:
            if task.passed:
                report.ok(f"normal use ({task.task_id})", "the expected answer came back")
            else:
                report.fix(
                    f"normal use ({task.task_id})", task.detail, "Check the prompt and expect_substring of this task check."
                )

    asyncio.run(online())
    if report.failed:
        return False
    out(f"  Ready. Scan it with: kritalon scan --target {spec} --html report.html")
    return True


def register(commands: Any) -> None:
    parser = commands.add_parser("doctor", help="check a bot's setup step by step and say what to do next")
    parser.add_argument("--target", required=True, help="for example http:staging")
    parser.add_argument("--offline", action="store_true", help="check only what needs no contact with the bot")
    parser.add_argument(
        "--env-file", action="append", default=[], metavar="PATH",
        help="an export of the deployment's settings, checked for production keys (names and known prefixes only)",
    )  # fmt: skip
    parser.set_defaults(
        handler=lambda args: EXIT_OK if diagnose(args.target, args.offline, env_files=tuple(args.env_file)) else EXIT_FAILED
    )
