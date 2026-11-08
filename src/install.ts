import fs from "node:fs";
import path from "node:path";
import { AGENTS, listAgents, type AgentDef } from "./agents.js";

const MARK = "--xray"; // marks hook commands that belong to us
export const MATCHER = "Read|Edit|Write|MultiEdit|NotebookEdit|Bash|WebFetch|Grep|Glob";

type Json = Record<string, any>;

function load(file: string): Json {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, "utf8");
  if (!text.trim()) return {};
  try { return JSON.parse(text) as Json; }
  catch {
    throw new Error(`${file} is not valid JSON (comments are not supported here) — refusing to touch it.`);
  }
}

function save(file: string, settings: Json): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(settings, null, 2) + "\n");
}

function backup(file: string): void {
  if (fs.existsSync(file) && !fs.existsSync(file + ".xray-backup")) {
    fs.copyFileSync(file, file + ".xray-backup");
  }
}

/** The command line that runs our hook, embedding the current cli.js path. */
export function hookCommand(entry: string): string {
  const script = fs.realpathSync(entry);
  return `"${process.execPath}" "${script}" hook ${MARK}`;
}
export function cursorHookCommand(entry: string, sub: "hook" | "cursor-hook"): string {
  const script = fs.realpathSync(entry);
  return `"${process.execPath}" "${script}" ${sub} ${MARK}`;
}

// ---------- claude-schema (Claude Code: settings.json → hooks.PreToolUse[]) ----------

export function upsertClaudeHook(file: string, command: string): void {
  backup(file);
  const settings = load(file);
  stripClaudeHook(file, settings);
  settings.hooks ??= {};
  settings.hooks.PreToolUse ??= [];
  settings.hooks.PreToolUse.push({ matcher: MATCHER, hooks: [{ type: "command", command, timeout: 10 }] });
  save(file, settings);
}

export function stripClaudeHook(file: string, given?: Json): number {
  const settings = given ?? load(file);
  const arr: any[] | undefined = settings.hooks?.PreToolUse;
  if (!Array.isArray(arr)) return 0;
  let removed = 0;
  for (const group of arr) {
    if (!Array.isArray(group.hooks)) continue;
    const before = group.hooks.length;
    group.hooks = group.hooks.filter((h: any) => !(typeof h?.command === "string" && h.command.includes(MARK)));
    removed += before - group.hooks.length;
  }
  settings.hooks.PreToolUse = arr.filter((g) => Array.isArray(g.hooks) && g.hooks.length > 0);
  if (settings.hooks.PreToolUse.length === 0) delete settings.hooks.PreToolUse;
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  if (!given) save(file, settings);
  return removed;
}

// ---------- zcode-schema (~/.zcode/cli/config.json → hooks.events.PreToolUse[]) ----------

export function upsertZcodeHook(file: string, command: string): void {
  backup(file);
  const settings = load(file);
  stripZcodeHook(file, settings);
  settings.hooks ??= {};
  settings.hooks.enabled = true; // configuration-file hooks are disabled by default
  settings.hooks.events ??= {};
  settings.hooks.events.PreToolUse ??= [];
  settings.hooks.events.PreToolUse.push({
    matcher: MATCHER,
    hooks: [{ type: "command", command, timeoutMs: 10000 }],
  });
  save(file, settings);
}

export function stripZcodeHook(file: string, given?: Json): number {
  const settings = given ?? load(file);
  const arr: any[] | undefined = settings.hooks?.events?.PreToolUse;
  if (!Array.isArray(arr)) return 0;
  let removed = 0;
  for (const group of arr) {
    if (!Array.isArray(group.hooks)) continue;
    const before = group.hooks.length;
    group.hooks = group.hooks.filter((h: any) => !(typeof h?.command === "string" && h.command.includes(MARK)));
    removed += before - group.hooks.length;
  }
  settings.hooks.events.PreToolUse = arr.filter((g) => Array.isArray(g.hooks) && g.hooks.length > 0);
  if (settings.hooks.events.PreToolUse.length === 0) delete settings.hooks.events.PreToolUse;
  if (Object.keys(settings.hooks.events).length === 0) {
    delete settings.hooks.events;
    if (settings.hooks.enabled === true) delete settings.hooks.enabled; // we turned it on only for ourselves
  }
  if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  if (!given) save(file, settings);
  return removed;
}

// ---------- cursor-schema (~/.cursor/hooks.json) ----------

const CURSOR_EVENTS = ["beforeShellExecution", "beforeReadFile"] as const;

export function upsertCursorHooks(file: string, commands: { event: string; command: string }[]): void {
  backup(file);
  const settings = load(file);
  stripCursorHooks(file, settings);
  settings.version ??= 1;
  settings.hooks ??= {};
  for (const { event, command } of commands) {
    settings.hooks[event] ??= [];
    settings.hooks[event].push({ command, timeout: 10 });
  }
  save(file, settings);
}

export function stripCursorHooks(file: string, given?: Json): number {
  const settings = given ?? load(file);
  let removed = 0;
  for (const event of CURSOR_EVENTS) {
    const arr: any[] | undefined = settings.hooks?.[event];
    if (!Array.isArray(arr)) continue;
    const before = arr.length;
    settings.hooks[event] = arr.filter((h: any) => !(typeof h?.command === "string" && h.command.includes(MARK)));
    removed += before - settings.hooks[event].length;
    if (settings.hooks[event].length === 0) delete settings.hooks[event];
  }
  if (!given) save(file, settings);
  return removed;
}

// ---------- high-level install / uninstall ----------

function installInto(agent: AgentDef, entry: string): string {
  const file = agent.settingsFile();
  if (agent.schema === "claude") {
    upsertClaudeHook(file, hookCommand(entry));
  } else if (agent.schema === "zcode") {
    upsertZcodeHook(file, hookCommand(entry));
  } else if (agent.schema === "cursor") {
    const sh = cursorHookCommand(entry, "cursor-hook");
    upsertCursorHooks(file, [
      { event: "beforeShellExecution", command: sh },
      { event: "beforeReadFile", command: sh },
    ]);
  } else {
    return `✖ ${agent.name}: no hook API yet (see \`agent-xray agents\`)`;
  }
  return `✔ ${agent.name}: hook installed in ${file}`;
}

export function install(target: string, project: boolean, entry: string = process.argv[1]): void {
  if (project || target === "project") {
    const file = path.join(process.cwd(), ".claude", "settings.local.json");
    upsertClaudeHook(file, hookCommand(entry));
    console.log(`✔ Claude Code (this project): hook installed in ${file}`);
    console.log(dim2(`  backup: ${file}.xray-backup`));
    console.log("\nNext:\n  1. Restart Claude Code (hooks are read at startup).\n  2. Run:  agent-xray watch  or  agent-xray dashboard");
    return;
  }
  const agents = listAgents().filter((a) => a.installed && a.schema !== "none");
  const chosen = target === "auto" ? agents : agents.filter((a) => a.id === target);
  if (chosen.length === 0) {
    console.log(target === "auto"
      ? "No supported agents detected. Try: agent-xray agents"
      : `Agent "${target}" is not installed or not supported. See: agent-xray agents`);
    process.exit(1);
  }
  let any = false;
  for (const a of chosen) {
    const res = installInto(a, entry);
    console.log(res);
    if (res.startsWith("✔")) any = true;
  }
  if (!any) process.exit(1);
  console.log("\nNext:\n  1. Restart the agent(s) — hooks are read at startup.\n  2. Run:  agent-xray dashboard   (or watch)");
  if (chosen.some((a) => a.id === "zcode")) console.log(dim2("  ZCode: hooks live in ~/.zcode/cli/config.json and need a ZCode restart."));
}

function dim2(s: string): string { return process.stdout.isTTY && !process.env.NO_COLOR ? `\x1b[2m${s}\x1b[0m` : s; }

export function uninstall(target: string, project: boolean): void {
  if (project || target === "project") {
    const file = path.join(process.cwd(), ".claude", "settings.local.json");
    if (!fs.existsSync(file)) { console.log(`Nothing to do: ${file} does not exist.`); return; }
    const n = stripClaudeHook(file);
    console.log(n ? `✔ Removed agent-xray hook from ${file}` : `No agent-xray hook found in ${file}`);
    return;
  }
  const installed = listAgents().filter((a) => a.installed && a.schema !== "none");
  const chosen = target === "auto" ? installed : installed.filter((a) => a.id === target);
  if (chosen.length === 0) { console.log("Nothing to uninstall."); return; }
  for (const a of chosen) {
    const file = a.settingsFile();
    if (!fs.existsSync(file)) { console.log(`Nothing to do: ${file} does not exist.`); continue; }
    const n = a.schema === "claude" ? stripClaudeHook(file)
      : a.schema === "zcode" ? stripZcodeHook(file)
      : a.schema === "cursor" ? stripCursorHooks(file)
      : 0;
    console.log(n ? `✔ Removed agent-xray hook from ${a.name} (${file})` : `No agent-xray hook found in ${a.name}`);
  }
}

export { AGENTS, listAgents };
