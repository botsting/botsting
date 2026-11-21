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
