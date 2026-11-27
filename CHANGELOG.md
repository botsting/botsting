# Changelog

## 0.0.4, unreleased (alpha)

**`botsting conclusion`: send a finished report and get our conclusion back.** It says what the result means, which finding to deal with first, what the scan did not test, and whether something that went wrong was a fault in BotSting and not in your bot. In exchange we get a real report to learn from.

- Running the command is the request: it shows what is being sent and where, and sends it. The names of who authorized and ran the test are removed first. `--without-conversations` also removes every message, reply, planted text and tool argument.
- At the end of a scan of your own bot, run at a terminal, the question is asked for you: `Send it? [Y/n]`, where Enter means yes and `w` sends it without the conversations. It is never asked in a script, a pipeline or an assistant, and `BOTSTING_NO_CONCLUSION=1` stops it.
- A report is kept until you ask for it to be removed: `botsting conclusion --remove REFERENCE`, or https://botsting.com/delete. The service does not keep your network address.
- `docs/never-do.md`, point 10, now says exactly this.

## 0.0.3, 2026-11-27 (alpha)

**The project is now called BotSting.** It was published as `kritalon` for versions 0.0.1 and 0.0.2. Everything that carried the old name changed with it:

- the package and the command: `pip install botsting`, `botsting scan ...` (was `kritalon`);
- the JavaScript packages: `botsting-harness` and `botsting` (were `kritalon-harness` and `kritalon`);
- the import: `import botsting.harness as pp` (was `kritalon.harness`);
- the settings: `BOTSTING_HARNESS_KEY`, `BOTSTING_CHALLENGE`, `BOTSTING_LIVE_ACTIONS` and the rest (were `KRITALON_...`);
- the request headers and the well-known addresses the harness and the scanner agree on, so a bot and a scanner must both be on this version or both on an older one;
- the file names a scan and the tool write: `scan.botsting.json`, `botsting.targets.json`, `botsting.authorizations.json`. Files written under the old names are not read; rename them or run `botsting authorize` again.

The `kritalon` packages stay on PyPI and npm with a note that points here.

Also in this version: every tool the assistant server offers says whether it only reads; the first scan tests text the bot reads from elsewhere; a marked tool's errors are shown in the terminal, each kind once.

## 0.0.2, 2026-11-26 (alpha)

No change to the code. The description shown on PyPI for 0.0.1 was the README from just before that upload, and still said the package was not on PyPI. This version carries the corrected text.

## 0.0.1, 2026-11-26 (alpha)

The first version on PyPI, under the earlier name (`pip install kritalon`). An alpha: names, options and file formats may still change. The JavaScript harness went to npm as `kritalon-harness` 0.1.0. This version contains:

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
- Bots built in a no-code builder: the fake secret travels in the chat request (`"harness": "inputs"`), with nothing added to the bot. `botsting init` writes the description for Flowise, Dify and Langflow.
- A first scan with no description file: `botsting scan http://localhost:8000/chat`. The harness tells the scanner which tools are marked and which secrets the bot reads, and provides the legitimate route for each secret through a pass phrase used in control conversations only.
- The first scan also tests text the bot reads from elsewhere, at each place the code reads with `pp.content(...)`; `--message` names the ordinary request to use.
- A Flask or Quart app is wrapped in place, so `app.run()` and its routes keep working and are wrapped.
- A secret that the bot's code reads only once, when it starts, is named by the first scan with what to change.
- A terminal summary that leads with the verdict, groups findings, and shows one real exchange.
- Anything a scan never tried (secret leaks, forbidden actions, text the bot reads from elsewhere) is named directly under the verdict in every output, and is never shown as a zero.
- `botsting doctor` checks a setup step by step and names the fix.
- `botsting mcp` lets a coding assistant set a bot up, scan it and read the report. It cannot authorize a test. Its `first_scan` tool scans a bot from its chat address alone, once a person has authorized that address.
- A Claude Code plugin in `integrations/claude-code`: that connection and one skill.
- `botsting demo` shows the whole flow on one machine in about a minute.

### Doing no harm
- No scan without a named person's authorization for one exact address, and proof of control of it.
- Tools must be recorders before any attack is sent.
- A bot carrying the harness refuses any test message it cannot verify.
- Live testing under caps: a tool runs for real only when a cap in the bot's code, a switch on the deployment, the signed session and the authorization all agree; a call outside a cap is recorded and not run.
- `botsting sterile-check` looks for production keys on a test deployment, by name and known prefix only.
- Limits on messages, tool calls and time, and a stop that takes effect at once.
- `botsting egress-trap`: a trap you run next to a bot to record and refuse its outbound web traffic, with a hash-chained log. No scan starts it by itself.
- Every scan request is labelled as test traffic.
- A name under `.localhost` counts as this machine only if every address it resolves to is a loopback one.
- Scanning an address again never loses a description that was edited by hand: the earlier one is kept beside it.

### Evidence
- JSON, Markdown and self-contained HTML reports, with the transcript behind every finding. The browser report groups findings by what was reached and folds all but the first of each group.
- A report says when the legitimate route for a secret was supplied by the test itself, and what that does and does not show.
- Findings and coverage mapped to public frameworks, with the tester and their independence stated.
- `botsting seal` and `check-seal`: an evidence bundle anyone can check later.
- `botsting ci` and a GitHub Action: scan, report, seal, and fail the build on a proven finding.
