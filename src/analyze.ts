import type { Rules, Verdict, XrayEvent } from "./types.js";
import { rank } from "./types.js";
import { evaluateCommand, evaluateFile, evaluateHost, worst } from "./rules.js";
import { redact } from "./redact.js";
import { shortPath } from "./paths.js";

export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
}

const WRITE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);
const READ_TOOLS = new Set(["Read", "Grep", "Glob"]);

const str = (v: unknown): string => (typeof v === "string" ? v : "");
const oneLine = (s: string, n = 300): string => {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
};

/**
 * Turn one PreToolUse payload into log events and one overall decision.
 * Pure function: no I/O, easy to test.
 */
export function analyze(
  input: HookInput, rules: Rules, now: number = Date.now()
): { events: XrayEvent[]; decision: Verdict } {
  const tool = input.tool_name ?? "unknown";
  const ti = input.tool_input ?? {};
  const cwd = input.cwd || process.cwd();
  const session = input.session_id ?? "unknown";
  const events: XrayEvent[] = [];
  const push = (e: Omit<XrayEvent, "ts" | "session" | "tool">) =>
    events.push({ ts: now, session, tool, ...e });

  let decision: Verdict = { level: "allow" };

  if (WRITE_TOOLS.has(tool) || READ_TOOLS.has(tool)) {
    const op = WRITE_TOOLS.has(tool) ? "write" : "read";
    const raw = str(ti.file_path) || str(ti.notebook_path) || str(ti.path) || cwd;
    const v = evaluateFile(raw, cwd, op, rules);
    push({ kind: "file", op, target: shortPath(v.path), level: v.level, reason: v.reason, rule: v.rule });
    decision = v;
  } else if (tool === "Bash") {
    const cmd = str(ti.command);
    const r = evaluateCommand(cmd, cwd, rules);
    const cmdVerdict = worst(r.findings);
    const reasons = r.findings.filter((f) => f.level === cmdVerdict.level).map((f) => f.reason).slice(0, 2);
    push({
      kind: "command", op: "exec", target: oneLine(redact(cmd)),
      level: cmdVerdict.level, reason: reasons.join("; ") || undefined, rule: cmdVerdict.rule,
    });
    const all: Verdict[] = [{ ...cmdVerdict, reason: reasons.join("; ") || undefined }];
    for (const h of r.hosts) {
      push({ kind: "network", op: "connect", target: h.host, level: h.verdict.level, reason: h.verdict.reason, rule: h.verdict.rule });
      all.push(h.verdict);
    }
    decision = worst(all);
  } else if (tool === "WebFetch") {
    let host = "";
    try { host = new URL(str(ti.url)).hostname; } catch { /* ignore */ }
    const v = host ? evaluateHost(host, false, rules) : { level: "allow" as const };
    push({ kind: "network", op: "connect", target: host || oneLine(str(ti.url), 80), level: v.level, reason: v.reason, rule: v.rule });
    decision = v;
  } else {
    push({ kind: "command", op: "exec", target: tool, level: "allow" });
  }

  if (rank(decision.level) === 0) decision = { level: "allow" };
  return { events, decision };
}
