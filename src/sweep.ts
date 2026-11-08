import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bold, dim, red, yellow, green, cyan } from "./render.js";

/**
 * `agent-xray sweep` — find the parasites AI agents leave behind: orphaned
 * processes, dev servers listening on the network, autostart entries and
 * disk hogs. Read-only: it reports and suggests, a human decides.
 */

export interface Finding {
  area: "process" | "port" | "autostart" | "disk";
  severity: "hot" | "warn" | "info";
  agent: string;
  detail: string;
  pid?: number;
  hint?: string;
}

// ---------- classification ----------

const AGENT_FINGERPRINTS: { re: RegExp; agent: string }[] = [
  { re: /antigravity/i, agent: "Antigravity" },
  { re: /cursor/i, agent: "Cursor" },
  { re: /windsurf|codeium/i, agent: "Windsurf" },
  { re: /agent-xray/i, agent: "agent-xray" },
  { re: /[Cc]laude/i, agent: "Claude" },
  { re: /gemini/i, agent: "Gemini" },
  { re: /zcode/i, agent: "ZCode" },
  { re: /\bcodex\b/i, agent: "Codex CLI" },
  { re: /\baider\b/i, agent: "Aider" },
  { re: /opencode/i, agent: "OpenCode" },
  { re: /\bollama\b/i, agent: "Ollama" },
  { re: /lm[ _-]?studio/i, agent: "LM Studio" },
];

const DEV_SERVER_RE = /node_modules\/\.bin\/(vite|next|webpack|nodemon|tsx|ts-node)|\b(vite|webpack-dev-server|next dev|nodemon|ts-node-dev)\b|esbuild --service|@esbuild\//i;
const AGENT_SERVICE_RE = /language_server|language-server/i;
// macOS built-in daemons that legitimately listen on all interfaces
const SYSTEM_DAEMON_RE = /^\/(usr\/libexec|usr\/sbin|System|sbin)\//;
const SYSTEM_DAEMON_NAMES = /^(rapportd|cupsd|mDNSResponder|ControlCe(nter)?|AirPlayUIAgent|sharingd|identityservicesd|imagent|distnoted|configd|notificationd|Dock|Finder|universalAccessd|hidd|bluetoothd)$/i;
const ORPHAN_SERVER_RE = /(^|[\/\s])(server|app|main|run_?\w*|dashboard|manage|uvicorn|gunicorn|flask|http\.server)\.(js|py|ts|mjs)\b/i;
export { SYSTEM_DAEMON_RE, ORPHAN_SERVER_RE };

export function classify(args: string): { agent: string; kind: "app" | "dev-server" | "service" | "other" } {
  let agent = "unknown";
  for (const f of AGENT_FINGERPRINTS) {
    if (f.re.test(args)) { agent = f.agent; break; }
  }
  if (DEV_SERVER_RE.test(args)) return { agent, kind: "dev-server" };
  if (AGENT_SERVICE_RE.test(args)) return { agent, kind: "service" };
  const bin = args.trim().split(/\s+/)[0]?.split("/").pop() ?? "";
  if (bin && AGENT_FINGERPRINTS.some((f) => {
    const m = f.re.source.replace(/\\b|\(|\)/g, "").split("|").filter(Boolean);
    return m.some((n) => bin.toLowerCase() === n.toLowerCase().replace(/\\|\^/g, ""));
  })) return { agent, kind: "app" };
  return { agent, kind: "other" };
}

/** ps etime → hours. Formats: [[dd-]hh:]mm:ss */
export function etimeHours(etime: string): number {
  const [dPart, hms = dPart] = /-/.test(etime) ? etime.split("-") : ["0", etime];
  const parts = hms.split(":").map(Number);
  const [dd = 0] = [Number(dPart)];
  const hh = parts.length === 3 ? parts[0] : 0;
  const mm = parts.length === 3 ? parts[1] : parts[0] ?? 0;
  const ss = parts.length === 3 ? parts[2] : parts[1] ?? 0;
  return dd * 24 + hh + mm / 60 + ss / 3600;
}

export function parsePsLine(line: string): { pid: number; ppid: number; cpu: number; etime: string; args: string } | null {
  const m = /^\s*(\d+)\s+(\d+)\s+([\d.]+)\s+(\S+)\s+(.+)$/.exec(line);
  if (!m) return null;
  return { pid: +m[1], ppid: +m[2], cpu: +m[3], etime: m[4], args: m[5] };
}

export function parseLsofLine(line: string): { command: string; pid: number; addr: string; port: number; exposed: boolean } | null {
  // node 1234 user 23u IPv4 0x… 0t0 TCP *:8787 (LISTEN)
  const t = line.trim().split(/\s+/);
  if (t.length < 9 || t[t.length - 1] !== "(LISTEN)") return null;
  const tcpIdx = t.indexOf("TCP");
  if (tcpIdx < 0 || tcpIdx + 1 >= t.length) return null;
  const addr = t[tcpIdx + 1];
  const port = +addr.replace(/^\[|\]$/g, "").split(":").pop()!;
  // exposed = bound to all interfaces: *:p, [::]:p — not localhost/127.0.0.1/[::1]
  const exposed = !/^(localhost|127\.|\[::1\])/i.test(addr);
  return { command: t[0], pid: +t[1], addr, port, exposed };
}

// ---------- scanners ----------

const run = (cmd: string, args: string[], timeoutMs = 15000): string => {
  try {
    const r = spawnSync(cmd, args, { encoding: "utf8", timeout: timeoutMs });
    return r.stdout ?? "";
  } catch { return ""; }
};

/** Working directory of a pid (empty string if unknown). */
function lsofCwd(pid: number): string {
  const out = run("lsof", ["-a", "-p", String(pid), "-d", "cwd", "-Fn"], 5000);
  const m = /^n(.+)$/m.exec(out);
  return m ? m[1] : "";
}

function scanProcesses(out: Finding[]): void {
  const text = run("ps", ["-axo", "pid=,ppid=,pcpu=,etime=,args="]);
  const runningApps = new Set<string>();
  const lines = text.split("\n").map(parsePsLine).filter(Boolean) as NonNullable<ReturnType<typeof parsePsLine>>[];
  for (const p of lines) {
    const { agent, kind } = classify(p.args);
    if (agent !== "unknown" && kind === "app") runningApps.add(agent);
  }
  for (const p of lines) {
    const { agent, kind } = classify(p.args);
    const hours = etimeHours(p.etime);
    if (kind === "dev-server") {
      out.push({
        area: "process", severity: hours >= 1 ? "warn" : "info", agent, pid: p.pid,
        detail: `dev server running for ${p.etime}  (${p.args.slice(0, 110)})`,
        hint: `kill ${p.pid}`,
      });
      continue;
    }
    if (kind === "service" && hours >= 24 && !runningApps.has(agent)) {
      out.push({
        area: "process", severity: "warn", agent, pid: p.pid,
        detail: `agent service alive ${p.etime}, but ${agent} itself is not running`,
        hint: `kill ${p.pid}`,
      });
      continue;
    }
    // orphaned server: detached from any app (PPID 1), alive for days
    if (p.ppid === 1 && hours >= 24 && !SYSTEM_DAEMON_RE.test(p.args) && ORPHAN_SERVER_RE.test(p.args)) {
      const cwd = lsofCwd(p.pid);
      const owner = classify(cwd + " " + p.args);
      const who = owner.agent !== "unknown" ? owner.agent : "unknown origin";
      out.push({
        area: "process", severity: "warn", agent: who, pid: p.pid,
        detail: `orphaned server alive ${p.etime} (detached, PPID 1)${cwd ? "  from " + cwd : ""}  (${p.args.slice(0, 80)})`,
        hint: `kill ${p.pid}`,
      });
    }
  }
}

function scanPorts(out: Finding[]): void {
  if (process.platform !== "darwin" && process.platform !== "linux") return;
  const text = run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"]);
  const procText = run("ps", ["-axo", "pid=,args="]);
  const argsOf = (pid: number) => procText.split("\n")
    .map((l) => /^\s*(\d+)\s+(.+)$/.exec(l)).find((m) => m && +m[1] === pid)?.[2] ?? "";
  for (const line of text.split("\n")) {
    const l = parseLsofLine(line);
    if (!l) continue;
    if (SYSTEM_DAEMON_NAMES.test(l.command) || SYSTEM_DAEMON_RE.test(argsOf(l.pid))) continue; // macOS built-ins
    const args = argsOf(l.pid);
    const cwd = l.exposed ? lsofCwd(l.pid) : "";
    const { agent } = classify(cwd + " " + args + " " + l.command);
    if (l.exposed) {
      const owner = agent !== "unknown" ? agent : args ? "unknown origin" : "unknown";
      out.push({
        area: "port", severity: "hot", agent: owner, pid: l.pid,
        detail: `${l.command} listens on ALL interfaces: *:${l.port} — visible from your network${cwd ? "  from " + cwd : ""}`,
        hint: `kill ${l.pid}  (or rebind to 127.0.0.1)`,
      });
    } else if (agent !== "unknown") {
      out.push({
        area: "port", severity: "info", agent, pid: l.pid,
        detail: `${l.command} listens on localhost :${l.port}`,
      });
    }
  }
}

const AUTOSTART_DIRS = [
  path.join(os.homedir(), "Library", "LaunchAgents"),
  "/Library/LaunchAgents",
  "/Library/LaunchDaemons",
];

function scanAutostart(out: Finding[]): void {
  for (const dir of AUTOSTART_DIRS) {
    let names: string[] = [];
    try { names = fs.readdirSync(dir); } catch { continue; }
    for (const name of names) {
      if (!name.endsWith(".plist")) continue;
      const file = path.join(dir, name);
      let text = "";
      try {
        const r = spawnSync("plutil", ["-convert", "json", "-o", "-", file], { encoding: "utf8", timeout: 5000 });
        text = (r.stdout && r.stdout.trim().startsWith("{")) ? r.stdout : fs.readFileSync(file, "utf8");
      } catch { continue; }
      for (const f of AGENT_FINGERPRINTS) {
        if (f.re.test(name) || f.re.test(text)) {
          out.push({
            area: "autostart", severity: "warn", agent: f.agent,
            detail: `${name} in ${dir} — starts at boot/login`,
            hint: `launchctl unload "${file}"  (or remove Login Item in System Settings)`,
          });
          break;
        }
      }
    }
  }
  if (process.platform === "darwin") {
    const r = spawnSync("osascript", ["-e", 'tell application "System Events" to get the name of every login item'], { encoding: "utf8", timeout: 5000 });
    for (const name of (r.stdout ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
      for (const f of AGENT_FINGERPRINTS) {
        if (f.re.test(name)) {
          out.push({
            area: "autostart", severity: "warn", agent: f.agent,
            detail: `login item "${name}" — starts at every login`,
            hint: `System Settings → General → Login Items → remove "${name}"`,
          });
          break;
        }
      }
    }
  }
}

const DISK_DIRS = [
  [".gemini", "Gemini"], [".claude", "Claude"], [".cursor", "Cursor"],
  [".agent-xray", "agent-xray"], [".codex", "Codex CLI"], [".config/opencode", "OpenCode"],
  [".codeium", "Windsurf"], [".ollama", "Ollama"], [".lmstudio", "LM Studio"],
  [".aider*", "Aider"],
] as const;

function scanDisk(out: Finding[]): void {
  const home = os.homedir();
  for (const [rel, agent] of DISK_DIRS) {
    const matches = rel.includes("*")
      ? fs.readdirSync(home).filter((n) => n.startsWith(rel.replace("*", ""))).map((n) => path.join(home, n))
      : [path.join(home, rel)];
    for (const dir of matches) {
      if (!fs.existsSync(dir)) continue;
      const kb = +run("du", ["-sk", dir], 20000).split("\t")[0] || 0;
      const mb = kb / 1024;
      if (mb >= 100) {
        out.push({
          area: "disk", severity: mb >= 1024 ? "warn" : "info", agent,
          detail: `${dir} — ${mb >= 1024 ? (mb / 1024).toFixed(1) + " GB" : Math.round(mb) + " MB"} on disk`,
          hint: `review and delete if not needed:  rm -rf "${dir}"`,
        });
      }
    }
  }
}

export function sweep(): Finding[] {
  const out: Finding[] = [];
  scanProcesses(out);
  scanPorts(out);
  scanAutostart(out);
  scanDisk(out);
  // dedup (lsof reports IPv4+IPv6 as separate lines)
  const seen = new Set<string>();
  const dedup = out.filter((f) => {
    const k = `${f.area}|${f.agent}|${f.detail}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const rank = { hot: 0, warn: 1, info: 2 };
  return dedup.sort((a, b) => rank[a.severity] - rank[b.severity] || a.area.localeCompare(b.area));
}

// ---------- report ----------

export function printSweep(findings: Finding[]): void {
  const hot = findings.filter((f) => f.severity === "hot");
  const warn = findings.filter((f) => f.severity === "warn");
  const info = findings.filter((f) => f.severity === "info");
  console.log(bold("agent-xray sweep") + dim(" — parasites AI agents left on this machine"));
  console.log();
  if (findings.length === 0) {
    console.log(green("  Clean. No agent leftovers found."));
    return;
  }
  const print = (f: Finding) => {
    const tag = f.severity === "hot" ? red("✖ HOT  ") : f.severity === "warn" ? yellow("⚠ WARN ") : green("✔ info ");
    console.log(`  ${tag} ${cyan(f.agent.padEnd(12))} ${f.detail}`);
    if (f.hint) console.log(dim(`          → ${f.hint}`));
  };
  for (const f of hot) print(f);
  for (const f of warn) print(f);
  for (const f of info) print(f);
  console.log();
  console.log(`  ${red("✖ hot")}: ${hot.length}   ${yellow("⚠ warn")}: ${warn.length}   ${green("✔ info")}: ${info.length}`);
  console.log(dim("  sweep only reports — nothing is killed without your command."));
}
