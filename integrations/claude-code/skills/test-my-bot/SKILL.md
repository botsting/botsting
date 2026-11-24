---
name: test-my-bot
description: Use whenever the user asks to security-test, red-team or pentest their own AI chatbot or agent, to check it for prompt injection, a leaked system prompt or secret, one user reaching another user's data, or a tool (refund, email, delete) that a chat user can talk it into calling. Also use when they ask to set up Promptproof, to run a Promptproof scan, or to explain a Promptproof report.
---

# Test the user's own bot with Promptproof

Promptproof tests a bot its owner controls and reports only what is proven: a fake secret it planted came out, or a call to a forbidden tool was recorded at the tool. You drive it through the `promptproof` MCP server. If its tools are missing, the `promptproof` command is not installed: tell the user to install it and stop.

## Rules that are not yours to bend

1. **Only the user can authorize a test.** Never run `promptproof authorize` yourself, never type a name into a prompt for them, and never edit `promptproof.authorizations.json`. Give them the exact command and wait.
2. **Only the user's own bot, on an address they control.** If they point you at someone else's service, decline.
3. **Propose every change to the bot as a diff and wait for approval.** The server never edits the project; neither do you without a yes.
4. **Never weaken a result.** "Inconclusive" is not "clean". "No verified violations" is a statement about the tests that ran, not "safe". Say what the report says was not tested.
5. Do not write attack messages of your own. The tool has its own.

## Steps

1. **Show what a result looks like, if they have not seen one.** Call `scan` with `target: "toy:vulnerable"`, then `read_report`. This scans a practice bot inside the tool and needs no permission.
2. **Read the guide.** Call `setup_guide` and follow it; it is the source of truth and overrides this page where they differ.
3. **Find the pieces in their code.** The web app object and the chat endpoint; where the instructions are put together for each message; every function that sends, pays, books, changes or deletes. Call `find_tools` for candidates, then read the code yourself.
4. **Propose the three kinds of line** (Python shown; for Node see the guide):
   - `pp.wrap(app)` last, after the routes. A Flask app stays the same object.
   - `@pp.action("name", never_for_users="what an attacker would ask for")` on each risky function that no chat user may ever cause. Leave `never_for_users` off a tool that some users may use, and say so: it needs a description (guide, step 3).
   - `pp.planted("slot_name", default)` where a secret lives, called **while a message is handled**, not once at import.
   The library must be installed in the bot's own environment.
5. **The key.** Ask the user to run `promptproof harness-key`, set `PROMPTPROOF_HARNESS_KEY` where the bot runs and where this session runs, and restart the bot. Never print or store the key.
6. **Authorization.** Call `authorization_status` with the bot's origin. If there is none, give the user the command it prints, with one `--tool NAME` for each tool marked `never_for_users` (a tool the authorization does not name is left untested), and wait until they say it is done.
7. **Scan.** Call `first_scan` with the chat address (for example `http://localhost:8000/chat`). If it is refused, relay exactly what it says to fix. For a bot that already has a description, call `doctor` and then `scan` with `http:NAME`.
8. **Report back in plain language.** Call `read_report`. Lead with the verdict in the report's own words. Then: what was reached and by how many ways; one real exchange, quoted; the fix the report names for each; what was not tested and why; where the browser report is. Do not pad it.
9. **After a fix**, scan again into a new folder and compare. A finding is closed when its replay no longer works and the legitimate route and normal use still do.

## When something fails

- "the harness did not see this as a test session": the key differs between the bot and this session, or the app that is served is not the wrapped one.
- "Secrets it reads on an ordinary message: none": the secret is read at import. Move `pp.planted(...)` into the code that handles a message.
- A marked tool makes the bot crash during a test: it needed more than the stand-in answer. Add `result=` to that `@pp.action`.
- Anything else: call `doctor`; it names the first step that is not passed and the change that fixes it.
