import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sweep, type Finding } from "./sweep.js";
import { listAgents } from "./agents.js";
import { loadConfig, verifySeal } from "./config.js";
import { eventsPath, xrayHome } from "./paths.js";
import { bold, dim, red, yellow, green, cyan } from "./render.js";

/**
 * `agent-xray audit` — a one-command security audit of a computer where AI
 * agents live: leftover processes and exposed ports, plaintext secrets in
 * agent configs, hook coverage, mode and tamper seal. Produces a score,
 * a terminal summary and a self-contained HTML report.
 */

// ---------- secrets scanning ----------

export interface SecretHit {
  type: string;
  masked: string;
  line: number;
}

const SECRET_PATTERNS: { re: RegExp; type: string }[] = [
  { re: /\bAKIA[0-9A-Z]{16}\b/g, type: "AWS access key" },
  { re: /\bsk-[A-Za-z0-9_-]{20,}\b/g, type: "OpenAI-style API key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, type: "GitHub token" },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, type: "Slack token" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, type: "Google API key" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, type: "private key block" },
];

const CREDENTIAL_FILENAME_RE = /(^|\/)(auth\.json|oauth_creds\.json|credentials|\.netrc|\.git-credentials|.*_creds.*|.*credential.*)$/i;

export const maskSecret = (s: string): string => s.slice(0, 6) + "…***";

/** Scan text for secret-shaped strings. Returns masked hits only. */
export function scanSecrets(text: string): SecretHit[] {
  const out: SecretHit[] = [];
  for (const { re, type } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      out.push({ type, masked: maskSecret(m[0]), line: text.slice(0, m.index).split("\n").length });
    }
  }
  return out;
}

const AUDIT_FILES = [
  [".claude/settings.json", false],
  [".claude/settings.local.json", false],
  [".claude/.credentials.json", true],
  [".zcode/cli/config.json", false],
  [".cursor/hooks.json", false],
  [".cursor/mcp.json", false],
  [".codex/auth.json", true],
  [".gemini/oauth_creds.json", true],
  [".gemini/settings.json", false],
  [".netrc", true],
] as const;

export interface SecretFinding extends SecretHit {
  file: string;
  /** files that are SUPPOSED to hold credentials → info, not hot */
  expected: boolean;
}

export function scanAgentConfigSecrets(home = os.homedir()): SecretFinding[] {
  const out: SecretFinding[] = [];
  for (const [rel, expected] of AUDIT_FILES) {
    const file = path.join(home, rel);
    if (!fs.existsSync(file)) continue;
    let text: string;
    try { text = fs.readFileSync(file, "utf8"); } catch { continue; }
    for (const hit of scanSecrets(text)) out.push({ ...hit, file, expected });
  }
  return out;
}

// ---------- hook coverage ----------

export interface CoverageRow {
  name: string;
  installed: boolean;
  supported: boolean;
  covered: boolean;
}

export function hookCoverage(home = os.homedir()): CoverageRow[] {
  return listAgents().map((a) => {
    const installed = a.installed;
    const supported = installed && a.schema !== "none";
    let covered = false;
    if (supported) {
      try { covered = fs.readFileSync(a.settingsFile(), "utf8").includes("--xray"); }
      catch { covered = false; }
    }
    return { name: a.name, installed, supported: !!supported, covered };
  });
}

// ---------- score ----------

export interface AuditResult {
  date: string;
  host: string;
  mode: string;
  sealOk: boolean;
  coverage: CoverageRow[];
  sweep: Finding[];
  secrets: SecretFinding[];
  score: number;
  grade: string;
  breakdown: { label: string; delta: number }[];
}

export function scoreAudit(r: Omit<AuditResult, "score" | "grade" | "breakdown">): AuditResult {
  let score = 100;
  const breakdown: { label: string; delta: number }[] = [];
  const take = (label: string, delta: number) => {
    if (delta === 0) return;
    score += delta;
    breakdown.push({ label, delta });
  };
  const hot = r.sweep.filter((f) => f.severity === "hot").length;
  const warn = r.sweep.filter((f) => f.severity === "warn").length;
  take(`exposed ports / hot parasites ×${hot}`, -15 * hot);
  take(`agent leftovers (warn) ×${warn}`, -5 * warn);
  const hotSecrets = r.secrets.filter((s) => !s.expected).length;
  const infoSecrets = r.secrets.filter((s) => s.expected).length;
  take(`plaintext secrets in agent configs ×${hotSecrets}`, -15 * hotSecrets);
  take(`credential files present ×${infoSecrets}`, -3 * infoSecrets);
  const uncovered = r.coverage.filter((c) => c.supported && !c.covered).length;
  take(`agents without X-ray coverage ×${uncovered}`, -10 * uncovered);
  if (r.mode === "observe") take("mode is observe (enforcement off)", -5);
  if (!r.sealOk) take("config tamper seal broken/absent", -10);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 95 ? "A+" : score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";
  return { ...r, score, grade, breakdown };
}

export function runAudit(): AuditResult {
  const base = {
    date: new Date().toISOString(),
    host: os.hostname(),
    mode: loadConfig().mode,
    sealOk: verifySeal().ok,
    coverage: hookCoverage(),
    sweep: sweep(),
    secrets: scanAgentConfigSecrets(),
  };
  return scoreAudit(base);
}

// ---------- terminal summary ----------

export function printAudit(r: AuditResult): void {
  const gColor = r.score >= 85 ? green : r.score >= 55 ? yellow : red;
  console.log(bold("agent-xray audit") + dim(` — ${r.host} — ${new Date(r.date).toLocaleString()}`));
  console.log();
  console.log(`  AI Safety Score: ${gColor(bold(String(r.score) + "/100"))}  grade ${gColor(bold(r.grade))}   mode: ${r.mode}`);
  console.log();
  const hot = r.sweep.filter((f) => f.severity === "hot");
  const warn = r.sweep.filter((f) => f.severity === "warn");
  const hotSec = r.secrets.filter((s) => !s.expected);
  console.log(`  ${hot.length ? red("✖") : green("✔")} exposed services / hot parasites : ${hot.length}`);
  console.log(`  ${warn.length ? yellow("⚠") : green("✔")} agent leftovers (warn)           : ${warn.length}`);
  console.log(`  ${hotSec.length ? red("✖") : green("✔")} plaintext secrets in configs     : ${hotSec.length}`);
  console.log(`  ${cyan("ℹ")} credential files present          : ${r.secrets.length - hotSec.length}`);
  for (const c of r.coverage.filter((c) => c.supported)) {
    console.log(`  ${c.covered ? green("✔") : yellow("⚠")} X-ray coverage: ${c.name}`);
  }
  console.log();
  console.log(bold("  Score breakdown"));
  for (const b of r.breakdown) console.log(`    ${b.delta < 0 ? red(String(b.delta)) : green("+" + b.delta)}  ${b.label}`);
  console.log(dim(`\n  full report: ${path.join(xrayHome(), "audit", "latest.html")}`));
}

// ---------- HTML report ----------

const esc = (s: string): string => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

function dial(score: number, grade: string): string {
  const angle = Math.round((score / 100) * 360) - 90;
  const color = score >= 85 ? "#4ade80" : score >= 55 ? "#fbbf24" : "#f87171";
  const rad = (a: number) => ((a + 90) * Math.PI) / 180;
  const x = 100 + 80 * Math.cos(rad(angle)), y = 100 + 80 * Math.sin(rad(angle));
  const large = score > 50 ? 1 : 0;
  return `<svg viewBox="0 0 200 200" width="200" height="200">
    <circle cx="100" cy="100" r="80" fill="none" stroke="#1d2836" stroke-width="14"/>
    <path d="M 100 20 A 80 80 0 ${large} 1 ${x.toFixed(1)} ${y.toFixed(1)}" fill="none" stroke="${color}" stroke-width="14" stroke-linecap="round"/>
    <text x="100" y="96" text-anchor="middle" fill="${color}" font-size="44" font-weight="700" font-family="monospace">${score}</text>
    <text x="100" y="128" text-anchor="middle" fill="#8b98a9" font-size="18" font-family="monospace">grade ${esc(grade)}</text>
  </svg>`;
}

export function buildHtml(r: AuditResult): string {
  const gColor = r.score >= 85 ? "#4ade80" : r.score >= 55 ? "#fbbf24" : "#f87171";
  const sevTag = (s: string) => s === "hot" ? '<span class="t hot">✖ HOT</span>' : s === "warn" ? '<span class="t warn">⚠ WARN</span>' : '<span class="t ok">✔ info</span>';
  const sweepRows = r.sweep.map((f) =>
    `<tr><td>${sevTag(f.severity)}</td><td>${esc(f.agent)}</td><td>${esc(f.detail)}${f.hint ? `<div class="hint">→ ${esc(f.hint)}</div>` : ""}</td></tr>`).join("") || '<tr><td colspan="3" class="empty">nothing found — clean</td></tr>';
  const secretRows = r.secrets.map((s) =>
    `<tr><td>${s.expected ? '<span class="t warn">⚠ stored</span>' : '<span class="t hot">✖ PLAINTEXT</span>'}</td><td>${esc(s.type)}</td><td><code>${esc(s.masked)}</code></td><td>${esc(s.file)}:${s.line}</td></tr>`)
    .join("") || '<tr><td colspan="4" class="empty">no secret-shaped strings in agent configs</td></tr>';
  const covRows = r.coverage.map((c) =>
    `<tr><td>${esc(c.name)}</td><td>${c.installed ? "installed" : "—"}</td><td>${c.supported ? (c.covered ? '<span class="t ok">✔ covered</span>' : '<span class="t warn">⚠ uncovered</span>') : '<span class="muted">no hook API</span>'}</td></tr>`).join("");
  const recs: string[] = [];
  if (r.sweep.some((f) => f.severity === "hot")) recs.push("Kill or rebind the exposed services — see the HOT rows (hints under each).");
  if (r.secrets.some((s) => !s.expected)) recs.push("Move plaintext API keys into a keychain / env file excluded from agent configs, then rotate the keys.");
  const uncovered = r.coverage.filter((c) => c.supported && !c.covered).map((c) => c.name);
  if (uncovered.length) recs.push(`Cover your agents with the X-ray hook:  agent-xray install   (covers: ${esc(uncovered.join(", "))})`);
  if (r.mode === "observe") recs.push("When you are ready for enforcement:  agent-xray mode guard   (observe only watches).");
  recs.push("Re-run after fixing:  agent-xray audit");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>agent-xray audit — ${esc(r.host)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing:border-box; margin:0; }
  body { background:#0b0f14; color:#d7dde6; font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; padding:28px; max-width:1080px; margin:0 auto; }
  header { display:flex; gap:26px; align-items:center; flex-wrap:wrap; margin-bottom:10px; }
  h1 { font-size:20px; } h1 span { color:#7aa2f7; }
  .meta { color:#5c6b7f; font-size:12px; margin-bottom:22px; }
  h2 { font-size:14px; color:#7aa2f7; margin:26px 0 10px; letter-spacing:.5px; text-transform:uppercase; }
  table { width:100%; border-collapse:collapse; background:#0e141c; border:1px solid #1d2836; border-radius:10px; overflow:hidden; }
  td, th { padding:8px 12px; border-top:1px solid #16202c; text-align:left; vertical-align:top; word-break:break-all; }
  th { color:#8b98a9; font-weight:400; border-top:none; background:#111823; }
  .t.hot { color:#f87171; font-weight:700; white-space:nowrap; }
  .t.warn { color:#fbbf24; font-weight:700; white-space:nowrap; }
  .t.ok { color:#4ade80; white-space:nowrap; }
  .muted { color:#5c6b7f; }
  .hint { color:#8b98a9; font-size:12px; margin-top:2px; }
  .empty { color:#5c6b7f; text-align:center; }
  .breakdown td:first-child { width:70%; }
  .delta-neg { color:#f87171; } .delta-pos { color:#4ade80; }
  .recs li { margin:6px 0 6px 18px; }
  .scorebox { display:flex; gap:20px; align-items:center; background:#111823; border:1px solid #1d2836; border-radius:12px; padding:16px 22px; }
  .scorebox .facts { color:#8b98a9; font-size:13px; }
  .scorebox .facts b { color:#d7dde6; }
  footer { margin-top:26px; color:#5c6b7f; font-size:12px; }
  a { color:#7aa2f7; }
</style></head><body>
<header>
  <h1>agent<span>-xray</span> audit</h1>
  ${dial(r.score, r.grade)}
  <div class="scorebox"><div class="facts">
    <b>${esc(r.host)}</b><br>
    date: ${esc(new Date(r.date).toLocaleString())}<br>
    mode: <b>${esc(r.mode)}</b>${r.sealOk ? "" : ' · <span class="t hot">tamper seal broken</span>'}<br>
    tool: agent-xray v0.6 · <a href="https://github.com/asanbay/agent-xray">github</a>
  </div></div>
</header>
<div class="meta">AI Safety Score — how safe this computer is while AI agents work on it. 100 = agents watched, nothing exposed, no plaintext secrets.</div>
<h2>Score breakdown</h2>
<table><tr><th>factor</th><th>delta</th></tr>
${r.breakdown.map((b) => `<tr><td>${esc(b.label)}</td><td class="${b.delta < 0 ? "delta-neg" : "delta-pos"}">${b.delta > 0 ? "+" : ""}${b.delta}</td></tr>`).join("") || '<tr><td colspan="2" class="empty">perfect baseline</td></tr>'}
</table>
<h2>1 · Parasites &amp; exposed services</h2>
<table><tr><th>level</th><th>agent</th><th>detail</th></tr>${sweepRows}</table>
<h2>2 · Secrets in agent configs</h2>
<table><tr><th>status</th><th>type</th><th>value</th><th>where</th></tr>${secretRows}</table>
<h2>3 · X-ray coverage of installed agents</h2>
<table><tr><th>agent</th><th>present</th><th>watched</th></tr>${covRows}</table>
<h2>4 · Recommendations</h2>
<ul class="recs">${recs.map((x) => `<li>${x}</li>`).join("")}</ul>
<footer>generated by agent-xray audit · events log: ${esc(eventsPath())} · secrets are masked, full values never leave this page</footer>
</body></html>`;
  return html;
}

export function writeAuditReport(r: AuditResult): string {
  const dir = path.join(xrayHome(), "audit");
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const html = buildHtml(r);
  const file = path.join(dir, `report-${r.date.replace(/[:.]/g, "-").slice(0, 19)}.html`);
  fs.writeFileSync(file, html);
  fs.writeFileSync(path.join(dir, "latest.html"), html); // stable name for humans
  return file;
}
