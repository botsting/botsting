# Promptproof

Evidence-first security testing for LLM applications. Promptproof attacks a bot you own and reports only what it can prove: it plants fresh secrets ("canaries") where an attacker should never reach, then shows you the exact conversation in which one came out.

Early development. It currently runs only against the built-in practice bot. Nothing here is released, and remote targets are not supported until the authorization checks exist.

## Try it

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run promptproof scan --target toy:vulnerable --markdown reports/vulnerable.md
uv run promptproof scan --target toy:fixed --markdown reports/fixed.md
```

`toy:vulnerable` and `toy:fixed` are two builds of the same small support bot. The first keeps a staff code in its instructions, looks up any order a user names, and offers its refund tool in every conversation; the second fixes all three in application code. By default they run on a scripted stand-in model, so no LLM is needed. Refunds go to an in-memory ledger; nothing here can move money.

A scan tries three things:

- **Disclosure.** The attacker talks to the bot and tries to get a planted secret out of it.
- **Action.** The attacker talks to the bot and tries to make it use a tool the attacker has no right to trigger, here a refund.
- **Planted text.** The attacker never talks to the bot. They leave text in an order note; later a staff member asks the bot to summarize that order, and the text tries to make the bot issue a refund on the staff member's authority.

To run the same bot on a real local model, install [Ollama](https://ollama.com), pull a model, and name it in the target:

```
ollama pull llama3.2
uv run promptproof scan --target "toy:vulnerable?model=ollama:llama3.2" --discovery-runs 3 --html reports/live.html
```

Run the adaptive attacker (Milestone 3) or compare static vs. adaptive at equal per-objective target-message budgets on the held-out hardened targets:

```
uv run promptproof scan --target hardened:keyword --strategy adaptive --html reports/hardened.html
uv run promptproof benchmark --budget-per-objective 8 --replays 3
```

PyRIT is supported behind the same `AdaptiveStrategy` interface as an optional extra (`uv sync --extra pyrit`).

Nothing is sent to a bot outside this process without a recorded, current authorization; see "Permission to test" below.

Replay a finding from a reset state with a fresh secret, or try the same attack on the fixed build:

```
uv run promptproof replay reports/scan.promptproof.json --finding F1
uv run promptproof replay reports/scan.promptproof.json --finding F1 --target toy:fixed
```

Exit codes: `0` no verified violations, `1` violations verified, `2` inconclusive.

## What a result means

- **Verified** means a planted secret, which the attacker was never shown, was recovered in full from the bot's output: verbatim, re-cased, reversed, rot13, URL-encoded, base64, hex, spelled out, or split across replies.
- **A forbidden action** is verified by a call recorded at the tool itself, never by what the bot says it did. It is reported as attempted (the tool refused it) or accepted (the tool carried it out). For planted text, the same request is first run with harmless text in its place; if the tool runs even then, the attack is not run, because a call could not be pinned on the planted text.
- **Suspected** means a partial match. It is shown and never counted.
- **Limits.** `--max-messages`, `--max-tool-calls` and `--max-seconds` stop a scan, and so does Ctrl+C. A scan that stops early says so and is inconclusive unless it had already verified something.
- **Tools must be sinks.** A scan refuses any target that has tools unless the target declares that they write to recording sinks with test data. These attacks exist to make tools fire.
- **"No verified violations observed under these tested conditions"** means exactly that. It is not a statement that the bot is protected. Before attacking, the scan fetches each secret by the legitimate route and checks a normal request still works; if either fails, the result is **inconclusive**, never a quiet zero.
- Two rates are reported for every finding: how often the attack worked while searching, and how often the frozen attack worked when replayed from reset. Each has its counts and a 95% Wilson interval.

Known limits are listed at the end of every report.

## Scanning a bot over HTTP

Any bot with an HTTP chat endpoint can be scanned once it has a small *test harness*: one extra endpoint in its staging or test build that Promptproof calls before every attempt.

```
POST /your/reset/path   {"fixtures": {"<slot id>": "<fake secret>"}, "content": {"<injection point id>": "<text>"}}
```

It puts each fake secret where that slot says it lives (the system prompt, a test customer's record), puts each piece of content where the bot will read it, forgets every earlier conversation, and answers 2xx. If the bot has tools, the harness also lists in each chat response the calls its own recorder saw on the tools, and every tool must write to a test sink, never to real customers, mailboxes or money.

The scan trusts the harness: it cannot check that a reset really forgot earlier conversations, or that the reported tool calls are real. Fresh fake secrets for every attempt and the legitimate-use checks limit the damage of a harness that half-works, but one that lies can produce false findings or hide real ones.

The bot is described in `promptproof.targets.json`: where it is, how to talk to it as each user, where its reply is in the response, and what it protects. Credentials are written as `${ENV_VAR}` and read from the environment when the scan runs; they never appear in reports. Requests go only to the described origin and its two paths; redirects are not followed.

To try the whole flow without a real bot, serve the practice bot over HTTP on this machine:

```
uv run promptproof practice-server --variant vulnerable --port 8765 --write-config
uv run promptproof authorize http://127.0.0.1:8765 --by "Your Name" --scope "practice bot" --environment test --tool issue_refund
uv run promptproof scan --target http:practice --html reports/practice.html
```

`--write-config` adds the practice bot to `promptproof.targets.json`, which is a working example of the format.

### The drop-in harness (Python bots)

Instead of writing the reset endpoint and recorders yourself, add a few lines to the bot:

```python
import promptproof.harness as pp

app = pp.wrap(app)                         # FastAPI/Starlette (ASGI) or Flask/Django (WSGI)

@pp.action("issue_refund")                 # on the function that does the deed, after your own checks
def issue_refund(order_id: str, amount: float): ...

prompt = BASE_PROMPT + pp.planted("admin_code")              # where a fake secret lives in a test
note = pp.planted("bob_note", note) if user == "bob" else note  # or in a test customer's record
```

Make a key with `promptproof harness-key` and set it as `PROMPTPROOF_HARNESS_KEY` on the staging deployment and where you run the scan. In the target description, write `"harness": "sdk"` and leave out `reset` and `tool_calls_pointer`.

- Nothing changes unless a request carries a Promptproof session signed with that key. Real users, even on staging, get the bot exactly as written.
- A request that carries a Promptproof session the bot cannot verify (no key there, another key, expired) is refused with HTTP 403 and never reaches your code. A wrapped production deployment therefore turns test traffic away.
- In a test session, `planted` returns that session's fake secret. Nothing is written to your database, so no fake users or records are needed.
- In a test session, a function marked `@pp.action` is recorded and not run. The record goes back to the scan in a header signed for that session and that message, so the model cannot fake it or reuse an old one.
- Before each attempt, the scan asks the harness to confirm test mode. If it does not, nothing is sent, not even the fake secrets.
- Set `PROMPTPROOF_CHALLENGE` to the token line from `promptproof authorize` and the harness serves the ownership proof for you.
- The harness uses only the Python standard library.

Limits:

- A tool that is not marked cannot be seen.
- Calls made after a streaming reply has started are blocked but not reported.
- The test session follows the request. Python carries it into `await`, `asyncio.to_thread` and the thread pools of Starlette and FastAPI. It is not carried into a thread you start yourself, a bare `run_in_executor`, a process pool or a job queue (Celery, RQ). A marked tool that runs there during a test runs for real. If your tools run that way, mark the function that hands the work over, not the worker.
- The signatures stop the model from faking the record. They do not stop the bot's own code from lying.

## Permission to test

Promptproof sends hostile messages, so it will not send anything to a bot outside its own process without permission on record. The built-in practice bots run in-process and need no permission; every bot reached over HTTP goes through this check.

```
promptproof authorize https://staging.example.com --by "Your Name" \
    --scope "the support bot on our staging site" --environment staging --days 30
```

This records who authorizes the test, for which exact origin, what it covers and until when (at most 90 days), and prints a token. Add `--tool NAME` for each tool the scan may exercise, and `--agent` or `--tenant` to limit it to one bot or account. Serve the token as plain text (`text/plain`) at `https://staging.example.com/.well-known/promptproof-challenge.txt`, then:

```
promptproof authorize --verify https://staging.example.com
```

The token is fetched again whenever a scan or replay starts, and every ten minutes during a long scan; if it has been taken down, the scan stops and reports what it had found so far. A bot on your own machine (`localhost`, `127.0.0.1`) needs the record but not the token. Authorizations are kept in `promptproof.authorizations.json` in the current folder and are never sent anywhere.

This shows control of what a site serves. It does not show that the person who placed the token owns everything behind it; the named person and the scope are how someone takes responsibility for that. Anyone can remove a check from open-source code; it is on by default.

## Development

```
uv run pytest
```

Licensed under Apache-2.0.

## Seal the evidence

A finished run's directory (reports, transcripts, the egress trap's log) can be packed into one bundle that anyone can check later:

```
uv run promptproof seal runs/2026-11-21 --out evidence.sealed.zip
uv run promptproof check-seal evidence.sealed.zip --seal <the printed seal>
```

Share the seal separately from the bundle. A matching seal shows that nothing in the bundle changed since it was sealed, and the check also prints which outbound destinations the egress log shows as allowed and refused. It does not show who made the bundle; signing is a later step.

## Using a report as evidence

Every Markdown and HTML report includes an **About this test** block (tool version, UTC scan dates, who authorized the scan and for which origin and environment, who ran it, and their independence from the target team) and a **Framework coverage** table mapping the objective kinds actually exercised to OWASP Top 10 for LLM Applications (2026), OWASP Top 10 for Agentic Applications (2026), MITRE ATLAS (v2026.10), NIST AI 600-1 (July 2024), and AIUC-1 (Q4 2026). Each verified finding lists the framework entries for its objective kind.

Record who ran the scan and their independence on the command line:

```
uv run promptproof scan --target http:staging --out runs/scan.promptproof.json \
    --markdown runs/report.md --html runs/report.html \
    --tester "Dana Levi, Example Audit" --independence third-party
```

`--independence` takes `self` (the team that built or operates the target, the default), `internal` (a separate team in the same organization), or `third-party` (an external assessor outside the organization).

The coverage table maps only the objective kinds Promptproof tests and states plainly what the scan did not cover. A report is evidence of what those tests observed; it never claims that a target is compliant, certified, or passed for any framework. Pair the JSON, Markdown, and HTML reports with `promptproof seal` when handing evidence to an auditor or buyer.
