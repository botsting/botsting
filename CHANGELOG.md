# Changelog

Nothing has been released yet. This lists what the first release will contain.

## Unreleased

### Finding problems
- Disclosure, forbidden-action and planted-text attacks, with a static list and an adaptive attacker (built in, or PyRIT behind the same interface).
- Fake secrets ("canaries") in two styles: a code, and an invented name for places where a bot would refuse to repeat a code-like value.
- A matcher that recognizes a leaked secret in plain text, re-cased, reversed, rot13, URL-encoded, base64, hex, spelled out or split across replies, with the odds of a chance match stated in every report's limitations.
- Every finding is replayed from a clean state, with discovery and reproduction rates and their intervals.
- A scan that could not have seen a failure is reported as inconclusive, never as clean.

### Connecting a bot
- Built-in practice bots (vulnerable, hardened, fixed).
- Any bot over HTTP, described in one JSON file.
- A drop-in harness for Python (ASGI and WSGI) and JavaScript (Node, Express, fetch-style): mark the risky tools and where a secret lives; nothing changes for real users.
- `harness_tools`: hand over a whole tool list (plain functions, OpenAI Agents SDK, LangChain, Claude Agent SDK); every tool not listed as read-only is recorded during a test, so a forgotten tool is blocked, not run.
- Bots built in a no-code builder: the fake secret travels in the chat request (`"harness": "inputs"`), with nothing added to the bot. `promptproof init` writes the description for Flowise, Dify and Langflow.
- A first scan with no description file: `promptproof scan http://localhost:8000/chat`. The harness tells the scanner which tools are marked and which secrets the bot reads, and provides the legitimate route for each secret through a pass phrase used in control conversations only.
- A Flask or Quart app is wrapped in place, so `app.run()` and its routes keep working and are wrapped.
- A secret that the bot's code reads only once, when it starts, is named by the first scan with what to change.
- A terminal summary that leads with the verdict, groups findings, and shows one real exchange.
- Anything a scan never tried (secret leaks, forbidden actions, text the bot reads from elsewhere) is named directly under the verdict in every output, and is never shown as a zero.
- `promptproof doctor` checks a setup step by step and names the fix.
- `promptproof mcp` lets a coding assistant set a bot up, scan it and read the report. It cannot authorize a test. Its `first_scan` tool scans a bot from its chat address alone, once a person has authorized that address.
- A Claude Code plugin in `integrations/claude-code`: that connection and one skill.
- `promptproof demo` shows the whole flow on one machine in about a minute.

### Doing no harm
- No scan without a named person's authorization for one exact address, and proof of control of it.
- Tools must be recorders before any attack is sent.
- A bot carrying the harness refuses any test message it cannot verify.
- Live testing under caps: a tool runs for real only when a cap in the bot's code, a switch on the deployment, the signed session and the authorization all agree; a call outside a cap is recorded and not run.
- `promptproof sterile-check` looks for production keys on a test deployment, by name and known prefix only.
- Limits on messages, tool calls and time, and a stop that takes effect at once.
- `promptproof egress-trap`: a trap you run next to a bot to record and refuse its outbound web traffic, with a hash-chained log. No scan starts it by itself.
- Every scan request is labelled as test traffic.
- A name under `.localhost` counts as this machine only if every address it resolves to is a loopback one.
- Scanning an address again never loses a description that was edited by hand: the earlier one is kept beside it.

### Evidence
- JSON, Markdown and self-contained HTML reports, with the transcript behind every finding. The browser report groups findings by what was reached and folds all but the first of each group.
- A report says when the legitimate route for a secret was supplied by the test itself, and what that does and does not show.
- Findings and coverage mapped to public frameworks, with the tester and their independence stated.
- `promptproof seal` and `check-seal`: an evidence bundle anyone can check later.
- `promptproof ci` and a GitHub Action: scan, report, seal, and fail the build on a proven finding.
