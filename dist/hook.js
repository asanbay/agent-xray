import { analyze } from "./analyze.js";
import { loadRules } from "./rules.js";
import { appendEvent, logError } from "./store.js";
async function readStdin() {
    const chunks = [];
    for await (const c of process.stdin)
        chunks.push(c);
    return Buffer.concat(chunks).toString("utf8");
}
/**
 * Claude Code PreToolUse hook.
 * stdin: JSON describing the tool call. stdout: optional JSON decision.
 * Fails OPEN: if anything goes wrong the agent keeps working and the error is logged.
 */
export async function runHook() {
    try {
        const input = JSON.parse(await readStdin());
        if (input.hook_event_name && input.hook_event_name !== "PreToolUse")
            return;
        const { events, decision } = analyze(input, loadRules());
        for (const e of events)
            appendEvent(e);
        if (decision.level !== "allow") {
            process.stdout.write(JSON.stringify({
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: decision.level === "block" ? "deny" : "ask",
                    permissionDecisionReason: `agent-xray: ${decision.reason ?? "flagged by rules"}`,
                },
            }) + "\n");
        }
    }
    catch (err) {
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
export async function runCursorHook() {
    try {
        const raw = JSON.parse(await readStdin());
        const session = typeof raw.conversation_id === "string" ? raw.conversation_id : "cursor";
        const cwd = typeof raw.cwd === "string" ? raw.cwd : process.cwd();
        const isRead = typeof raw.file_path === "string" && raw.file_path !== "";
        const input = isRead
            ? { hook_event_name: "PreToolUse", tool_name: "Read", session_id: session, cwd,
                tool_input: { file_path: raw.file_path } }
            : { hook_event_name: "PreToolUse", tool_name: "Bash", session_id: session, cwd,
                tool_input: { command: typeof raw.command === "string" ? raw.command : "" } };
        const { events, decision } = analyze(input, loadRules());
        for (const e of events)
            appendEvent(e);
        if (decision.level === "block") {
            process.stdout.write(JSON.stringify({
                permission: "deny",
                user_message: `agent-xray: ${decision.reason ?? "flagged by rules"}`,
                agent_message: `agent-xray: blocked — ${decision.reason ?? "flagged by rules"}`,
            }) + "\n");
        }
        else if (decision.level === "warn") {
            process.stdout.write(JSON.stringify({
                permission: "ask",
                user_message: `agent-xray: ${decision.reason ?? "flagged by rules"}`,
            }) + "\n");
        }
    }
    catch (err) {
        logError(err);
    }
}
