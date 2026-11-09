#!/usr/bin/env node
import fs from "node:fs";
import { spawn } from "node:child_process";
import { runHook, runCursorHook } from "./hook.js";
import { install, uninstall, listAgents } from "./install.js";
import { demo } from "./demo.js";
import { readEvents, followEvents } from "./store.js";
import { startDashboard } from "./dashboard.js";
import { buildReport, printReport } from "./report.js";
import { sweep, printSweep } from "./sweep.js";
import { runAudit, printAudit, writeAuditReport } from "./audit.js";
import { startProxy } from "./proxy.js";
import { bold, dim, formatEvent, sessionHeader } from "./render.js";
import { customRulesPath, eventsPath, configPath } from "./paths.js";
import { DEFAULT_RULES } from "./rules.js";
import { loadConfig, setMode, seal, type Mode } from "./config.js";
import type { XrayEvent } from "./types.js";

const HELP = `${bold("agent-xray")} — X-ray for AI coding agents

Usage:
  agent-xray agents                  show agents on this machine and support status
  agent-xray install [agent] [--guard]   add the hook (default mode: observe — log only);
                                     --guard starts in guard mode (warn→ask, block→deny);
                                     agent = claude | zcode | cursor | project
  agent-xray mode <observe|guard>    switch mode (run this yourself, not via the agent);
                                     reseals config, tampering is flagged
  agent-xray uninstall [agent]       remove our hooks again
  agent-xray watch                   live feed of what the agents touch (run in a second terminal)
  agent-xray dashboard [--port N]    web dashboard on localhost (default port 8787)
  agent-xray report [--all]          summary + risk grade for the last session (or everything)
  agent-xray rules                   show where to customise rules
  agent-xray sweep [--json]          find AI-agent leftovers: orphan processes, open ports,
                                     autostart entries, disk hogs (reports, never kills)
  agent-xray audit                   full AI-safety audit: score, secrets in agent configs,
                                     coverage, parasites → HTML report in ~/.agent-xray/audit
  agent-xray proxy [--port N]        localhost proxy: domain-level visibility for ANY agent
                                     (run:  HTTPS_PROXY=http://127.0.0.1:8080 <your-agent>)
  agent-xray demo [--log]            simulated session; --log also writes it to the event log

Modes:   observe = log everything, block nothing (default)   guard = warn→ask, block→deny
Levels:  ✔ ok = allowed   ⚠ WARN = the agent asks you first   ✖ BLOCK = denied
Log:     ${eventsPath()}
Config:  ${configPath()}`;

function modeCmd(m: unknown): void {
  if (m !== "observe" && m !== "guard") {
    console.log(`Usage: agent-xray mode <observe|guard>   (current: ${loadConfig().mode})`);
    process.exit(1);
  }
  setMode(m as Mode);
  console.log(`✔ mode: ${m}   (${m === "guard" ? "warn→ask, block→deny" : "log only, nothing is denied"})`);
  console.log(dim("config + rules resealed — manual edits will now be flagged as tampering"));
}

function agentsList(): void {
  console.log(bold("Agents on this machine"));
  for (const a of listAgents()) {
    const mark = !a.installed ? dim("– not installed")
      : a.schema === "none" ? dim("… detected, no hook API yet")
      : a.schema === "cursor" ? "✔ supported (beta)"
      : "✔ supported";
    console.log(`  ${a.name.padEnd(14)} ${mark}`);
    if (a.installed) console.log(dim(`     ${a.note}`));
  }
  console.log(dim("\ninstall:  agent-xray install          (all supported, detected automatically)"));
  console.log(dim("single:   agent-xray install zcode   |  claude  |  cursor  |  project"));
}

function watch(): void {
  const file = eventsPath();
  console.log(bold("agent-xray") + dim(`  watching ${file}   (Ctrl+C to exit)`));
  let lastSession = "";
  const print = (e: XrayEvent) => {
    if (e.session !== lastSession) { console.log(sessionHeader(e.session)); lastSession = e.session; }
    console.log(formatEvent(e));
  };
  readEvents().slice(-15).forEach(print);
  followEvents(print);
}

function openBrowser(url: string): void {
  try {
    if (process.platform === "darwin") spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
    else if (process.platform !== "win32") spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref();
  } catch { /* the user can open the URL manually */ }
}

async function dashboard(port: number): Promise<void> {
  const { url } = await startDashboard({ port });
  openBrowser(url);
  console.log(bold("agent-xray") + dim(`  dashboard → ${url}   (Ctrl+C to exit)`));
}

function report(all: boolean): void {
  const events = readEvents();
  const last = events[events.length - 1]?.session;
  const scoped = all ? events : events.filter((e) => e.session === last);
  printReport(buildReport(scoped), all);
}

function rules(): void {
  const n = (a: unknown[]) => a.length;
  console.log(bold("Rules"));
  console.log(`  built-in : ${n(DEFAULT_RULES.file.block)} blocked paths, ${n(DEFAULT_RULES.file.warn)} warned paths, ${n(DEFAULT_RULES.command.block)}+${n(DEFAULT_RULES.command.warn)} command rules, ${n(DEFAULT_RULES.network.warn)} flagged hosts`);
  console.log(`  custom   : ${customRulesPath()} ${fs.existsSync(customRulesPath()) ? "(found)" : dim("(not created yet)")}`);
  console.log(dim(`\nExample rules.json — arrays are appended to the built-ins, "allow" wins over block/warn:`));
  console.log(JSON.stringify({
    file: { allow: ["~/work/**/.env"], warn: ["~/Documents/taxes/**"] },
    network: { allow: ["internal.mycompany.com"] },
    command: { warn: [{ pattern: "\\\\bterraform\\\\s+apply\\\\b", reason: "infra change" }] },
  }, null, 2));
}

function parsePort(args: string[]): number {
  const i = args.indexOf("--port");
  const v = i >= 0 ? Number(args[i + 1]) : NaN;
  return Number.isInteger(v) && v > 0 && v < 65536 ? v : 8787;
}

process.stdout.on("error", (e: NodeJS.ErrnoException) => { if (e.code === "EPIPE") process.exit(0); });

const [, , cmd, ...args] = process.argv;
const flag = (f: string) => args.includes(f);

switch (cmd) {
  case "hook": await runHook(); break;
  case "cursor-hook": await runCursorHook(); break;
  case "agents": agentsList(); break;
  case "install":
    install(args.find((a) => !a.startsWith("--")) ?? "auto", flag("--project"));
    if (flag("--guard")) { setMode("guard"); console.log("✔ mode: guard   (warn→ask, block→deny)"); }
    else if (!fs.existsSync(configPath())) console.log(dim("mode: observe (default — log only). Switch with:  agent-xray mode guard"));
    break;
  case "mode": modeCmd(args[0]); break;
  case "uninstall": uninstall(args.find((a) => !a.startsWith("--")) ?? "auto", flag("--project")); break;
  case "watch": watch(); break;
  case "dashboard": await dashboard(parsePort(args)); break;
  case "proxy": {
    const { url } = await startProxy({ port: parsePort(args) });
    console.log(bold("agent-xray") + dim(`  proxy → ${url}   (Ctrl+C to exit)`));
    console.log(dim("  point any agent at it:  HTTPS_PROXY=" + url + " HTTP_PROXY=" + url + " <agent>"));
    console.log(dim(`  session appears in the log and dashboard as "proxy"`));
    break;
  }
  case "report": report(flag("--all")); break;
  case "sweep": {
    const findings = sweep();
    if (flag("--json")) console.log(JSON.stringify(findings, null, 2));
    else printSweep(findings);
    break;
  }
  case "audit": {
    const result = runAudit();
    printAudit(result);
    const file = writeAuditReport(result);
    if (!flag("--no-open") && process.platform === "darwin") {
      try { spawn("open", [file], { detached: true, stdio: "ignore" }).unref(); } catch { /* open manually */ }
    }
    break;
  }
  case "rules": rules(); break;
  case "demo": await demo(flag("--log")); break;
  default: console.log(HELP); process.exit(cmd && cmd !== "help" && cmd !== "--help" ? 1 : 0);
}
