import { analyze, type HookInput } from "./analyze.js";
import { loadRules } from "./rules.js";
import { appendEvent, logError } from "./store.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Claude Code PreToolUse hook.
 * stdin: JSON describing the tool call. stdout: optional JSON decision.
 * Fails OPEN: if anything goes wrong the agent keeps working and the error is logged.
 */
export async function runHook(): Promise<void> {
  try {
    const input = JSON.parse(await readStdin()) as HookInput;
    if (input.hook_event_name && input.hook_event_name !== "PreToolUse") return;
    const { events, decision } = analyze(input, loadRules());
    for (const e of events) appendEvent(e);
    if (decision.level !== "allow") {
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: decision.level === "block" ? "deny" : "ask",
            permissionDecisionReason: `agent-xray: ${decision.reason ?? "flagged by rules"}`,
          },
        }) + "\n"
      );
    }
  } catch (err) {
    logError(err);
  }
}
