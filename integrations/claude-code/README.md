# Kritalon for Claude Code

A plugin that lets Claude Code set Kritalon up in your project, scan your own bot and read the report back to you. It holds one connection (the `kritalon mcp` server, which runs on your machine) and one skill that tells the assistant how to use it and what it must never do.

Not published anywhere yet. To try it from a checkout of this repository:

```
uv tool install git+https://github.com/kritalon/kritalon          # the kritalon command, once
git clone https://github.com/kritalon/kritalon                    # the plugin lives in the repository
claude --plugin-dir kritalon/integrations/claude-code             # start Claude Code with the plugin
```

Then, in your bot's project, ask: "test my bot for prompt injection".

Without the plugin, the same server can be added by hand: `claude mcp add kritalon -- kritalon mcp`.

## What the assistant can do

- Read the setup guide, and list the functions in your project that look like risky tools.
- Propose the lines to add to your bot. You approve each change; the server never edits your project.
- Check your setup step by step and say what to fix next.
- Scan your bot from its chat address once you have authorized it, and read the report back.
- Scan the built-in practice bots at any time, to show what a result looks like.

## What it cannot do

- **Authorize a test.** That is a person taking responsibility by name. You run `kritalon authorize` in your own terminal; the server has no tool that records one, and a scan of your bot is refused until you have.
- Read or write outside the folder Claude Code was started in.
- Send anything to a bot before an authorization for that exact address is on record.

Nothing leaves your machine except the messages to the bot you named.
