"""`botsting authorize`: record who allows a target to be tested, and prove control of it.

    botsting authorize https://staging.example.com --by "Dana Levi" \\
        --scope "support bot on the staging site" --environment staging --days 30
    botsting authorize --verify https://staging.example.com
    botsting authorize --list

Exit codes: 0 done, 2 refused or failed.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from botsting.core.authorization import (
    CHALLENGE_PATH,
    DEFAULT_STORE,
    ENVIRONMENTS,
    MAX_DAYS,
    AuthorizationError,
    AuthorizationStore,
    check_proof,
    new_authorization,
)
from botsting.exits import EXIT_FAILED, EXIT_OK


def register(commands: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    parser = commands.add_parser(
        "authorize",
        help="record who allows a target to be tested, and prove control of it",
        description=(
            "Nothing is sent to a target outside this process without an authorization: a named person, "
            "a scope, an environment and an expiry, and, across a network, a token served by the target's "
            "own site."
        ),
    )
    parser.add_argument("origin", nargs="?", help="where the bot is reached, e.g. https://staging.example.com")
    parser.add_argument("--by", help="the person who authorizes the test")
    parser.add_argument("--scope", help="what may be tested, in a sentence")
    parser.add_argument("--environment", choices=ENVIRONMENTS, help="which environment the origin is")
    parser.add_argument("--days", type=int, default=30, help=f"how long it lasts, 1 to {MAX_DAYS} days (default 30)")
    parser.add_argument(
        "--tool", action="append", default=[], metavar="NAME",
        help="a tool the scan may exercise (repeat for each); tools not named here cannot be tested",
    )  # fmt: skip
    parser.add_argument(
        "--live-tool", action="append", default=[], metavar="NAME",
        help=(
            "a tool the test may carry out FOR REAL, inside the caps written in the bot's code "
            "(repeat for each; implies --tool). Without this, tools are only recorded"
        ),
    )  # fmt: skip
    parser.add_argument("--agent", default="", help="the one agent or bot id covered, if the target names one")
    parser.add_argument("--tenant", default="", help="the one tenant or account covered, if the target names one")
    parser.add_argument("--verify", metavar="ORIGIN", help="check that the origin serves the token, and record it")
    parser.add_argument("--list", action="store_true", help="show the recorded authorizations")
    parser.add_argument("--store", default=str(DEFAULT_STORE), help=f"where they are kept (default {DEFAULT_STORE})")
    parser.set_defaults(handler=_authorize)


def _authorize(args: argparse.Namespace) -> int:
    store = AuthorizationStore(Path(args.store))
    try:
        if args.list:
            return _list(store)
        if args.verify:
            return _verify(store, args.verify)
        return _create(store, args)
    except (AuthorizationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED


def _create(store: AuthorizationStore, args: argparse.Namespace) -> int:
    missing = [flag for flag, value in (("origin", args.origin), ("--by", args.by), ("--scope", args.scope), ("--environment", args.environment)) if not value]
    if missing:
        print(f"error: also give {', '.join(missing)}", file=sys.stderr)
        return EXIT_FAILED
    authorization = new_authorization(
        args.origin, args.by, args.scope, args.environment, args.days,
        allowed_tools=[*args.tool, *args.live_tool], agent_id=args.agent, tenant=args.tenant,
        live_tools=args.live_tool,
    )  # fmt: skip
    store.add(authorization)
    print(f"Recorded: {authorization.authorized_by} authorizes testing {authorization.origin}")
    print(f"  scope: {authorization.scope}")
    print(f"  tools that may be exercised: {', '.join(authorization.allowed_tools) or 'none'}")
    if authorization.live_tools:
        print(f"  tools that may be CARRIED OUT FOR REAL, inside the bot's caps: {', '.join(authorization.live_tools)}")
        print("  Real money, messages or records may change, up to those caps. Check the caps in the bot's code first.")
    if authorization.agent_id or authorization.tenant:
        print(f"  agent: {authorization.agent_id or 'any'}; tenant: {authorization.tenant or 'any'}")
    print(f"  environment: {authorization.environment}, until {authorization.expires_at}")
    if authorization.environment == "production":
        print("  Note: this is a production system. Tests send hostile messages and may trigger the bot's tools.")
    if not authorization.needs_proof:
        print("This origin is on this machine, so no proof of control is needed. Scans may now run against it.")
        return EXIT_OK
    print()
    print("To prove you control this origin, serve this exact line as plain text at")
    print(f"  {authorization.challenge_url()}")
    print()
    print(f"  {authorization.challenge_line()}")
    print()
    print(f"Then run: botsting authorize --verify {authorization.origin}")
    print(f"Keep it there while you scan: it is checked again each time a scan starts. Store: {store.path}")
    return EXIT_OK


def _verify(store: AuthorizationStore, origin: str) -> int:
    authorization = store.find(origin)
    if authorization is None:
        print(f"error: no authorization for {origin}; create one first", file=sys.stderr)
        return EXIT_FAILED
    now = datetime.now(UTC)
    if authorization.expired(now):
        print(f"error: the authorization for {authorization.origin} expired at {authorization.expires_at}", file=sys.stderr)
        return EXIT_FAILED
    result = check_proof(authorization)
    if not result.ok:
        print(f"Not verified: {result.detail}", file=sys.stderr)
        print(f"Serve '{authorization.challenge_line()}' at {CHALLENGE_PATH} over https and try again.", file=sys.stderr)
        return EXIT_FAILED
    store.mark_verified(authorization.origin, now)
    print(f"Verified: {result.detail}. Scans of {authorization.origin} may run until {authorization.expires_at}.")
    return EXIT_OK


def _list(store: AuthorizationStore) -> int:
    authorizations = store.load()
    if not authorizations:
        print(f"No authorizations recorded in {store.path}.")
        return EXIT_OK
    now = datetime.now(UTC)
    for a in authorizations:
        if a.expired(now):
            state = "expired"
        elif not a.needs_proof:
            state = "ready (on this machine)"
        else:
            state = f"verified {a.verified_at}" if a.verified_at else "not verified yet"
        print(f"{a.origin}  {state}")
        print(f"  by {a.authorized_by}; {a.environment}; until {a.expires_at}; scope: {a.scope}")
    return EXIT_OK
