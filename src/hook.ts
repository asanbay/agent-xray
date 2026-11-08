import { analyze, type HookInput } from "./analyze.js";
import { loadRules } from "./rules.js";
import { appendEvent, logError } from "./store.js";
import { loadConfig, verifySeal, type SealCheck } from "./config.js";
import type { Verdict } from "./types.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/** Log a seal mismatch: the dashboard should scream about this. */
function tamperEvent(session: string, tool: string, seal: SealCheck): void {
  appendEvent({
    ts: Date.now(), session, tool, kind: "command", op: "exec",
    target: seal.detail, level: "block",
    reason: "config tampered — only a human may run `agent-xray mode` (🫖)",
  });
}

/**
 * Apply the mode to a decision.
 * observe (default): log everything, decide nothing — the agent keeps working.
 * guard: warn → ask, block → deny; a broken seal forces deny.
 */
function enforce(decision: Verdict, mode: string, seal: SealCheck): Verdict {
  if (mode !== "guard") return { level: "allow" };
  if (!seal.ok) {
    return { level: "block", reason: `${seal.detail} — a human must reseal (🫖)` };
  }
  return decision;
}

/**
 * Claude Code / ZCode PreToolUse hook.
 * stdin: JSON describing the tool call. stdout: optional JSON decision.
 * Fails OPEN: if anything goes wrong the agent keeps working and the error is logged.
 */
export async function runHook(): Promise<void> {
  try {
    const input = JSON.parse(await readStdin()) as HookInput;
    if (input.hook_event_name && input.hook_event_name !== "PreToolUse") return;
    const rules = loadRules();
    const { events, decision } = analyze(input, rules);
    for (const e of events) appendEvent(e);
    const cfg = loadConfig();
    const seal = verifySeal();
    if (!seal.ok) tamperEvent(input.session_id ?? "unknown", input.tool_name ?? "unknown", seal);
    const final = enforce(decision, cfg.mode, seal);
    if (final.level !== "allow") {
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: final.level === "block" ? "deny" : "ask",
            permissionDecisionReason: `agent-xray: ${final.reason ?? "flagged by rules"}`,
          },
        }) + "\n"
      );
    }
  } catch (err) {
    logError(err);
  }
}

/**
 * Cursor hook adapter (beforeShellExecution / beforeReadFile).
 * stdin: { hook_event_name, command?, cwd?, file_path?, conversation_id?, ... }.
 * stdout: { permission: allow|ask|deny, user_message?, agent_message? }.
 * NOTE: beforeReadFile payloads contain file contents — we never read or log them,
 * only the path goes through the rules engine.
 */
export async function runCursorHook(): Promise<void> {
  try {
    const raw = JSON.parse(await readStdin()) as Record<string, unknown>;
    const session = typeof raw.conversation_id === "string" ? raw.conversation_id : "cursor";
    const cwd = typeof raw.cwd === "string" ? raw.cwd : process.cwd();
    const isRead = typeof raw.file_path === "string" && raw.file_path !== "";
    const input: HookInput = isRead
      ? { hook_event_name: "PreToolUse", tool_name: "Read", session_id: session, cwd,
          tool_input: { file_path: raw.file_path } }
      : { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: session, cwd,
          tool_input: { command: typeof raw.command === "string" ? raw.command : "" } };
    const rules = loadRules();
    const { events, decision } = analyze(input, rules);
    for (const e of events) appendEvent(e);
    const cfg = loadConfig();
    const seal = verifySeal();
    if (!seal.ok) tamperEvent(session, input.tool_name ?? "unknown", seal);
    const final = enforce(decision, cfg.mode, seal);
    if (final.level === "block") {
      process.stdout.write(JSON.stringify({
        permission: "deny",
        user_message: `agent-xray: ${final.reason ?? "flagged by rules"}`,
        agent_message: `agent-xray: blocked — ${final.reason ?? "flagged by rules"}`,
      }) + "\n");
    } else if (final.level === "warn") {
      process.stdout.write(JSON.stringify({
        permission: "ask",
        user_message: `agent-xray: ${final.reason ?? "flagged by rules"}`,
      }) + "\n");
    }
  } catch (err) {
    logError(err);
  }
}
