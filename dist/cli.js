#!/usr/bin/env node
import fs from "node:fs";
import { spawn } from "node:child_process";
import { runHook } from "./hook.js";
import { install, uninstall } from "./install.js";
import { demo } from "./demo.js";
import { readEvents, followEvents } from "./store.js";
import { startDashboard } from "./dashboard.js";
import { buildReport, printReport } from "./report.js";
import { bold, dim, formatEvent, sessionHeader } from "./render.js";
import { customRulesPath, eventsPath } from "./paths.js";
import { DEFAULT_RULES } from "./rules.js";
const HELP = `${bold("agent-xray")} — X-ray for AI coding agents

Usage:
  agent-xray install [--project]     add the guard hook to Claude Code (user-level, or ./.claude/settings.local.json)
  agent-xray uninstall [--project]   remove it again
  agent-xray watch                   live feed of what the agent touches (run in a second terminal)
  agent-xray dashboard [--port N]    web dashboard on localhost (default port 8787)
  agent-xray report [--all]          summary + risk grade for the last session (or everything)
  agent-xray rules                   show where to customise rules
  agent-xray demo [--log]            simulated session; --log also writes it to the event log

Levels:  ✔ ok = allowed   ⚠ WARN = Claude Code asks you first   ✖ BLOCK = denied
Log:     ${eventsPath()}`;
function watch() {
    const file = eventsPath();
    console.log(bold("agent-xray") + dim(`  watching ${file}   (Ctrl+C to exit)`));
    let lastSession = "";
    const print = (e) => {
        if (e.session !== lastSession) {
            console.log(sessionHeader(e.session));
            lastSession = e.session;
        }
        console.log(formatEvent(e));
    };
    readEvents().slice(-15).forEach(print);
    followEvents(print);
}
function openBrowser(url) {
    try {
        if (process.platform === "darwin")
            spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
        else if (process.platform !== "win32")
            spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref();
    }
    catch { /* the user can open the URL manually */ }
}
async function dashboard(port) {
    const { url } = await startDashboard({ port });
    openBrowser(url);
    console.log(bold("agent-xray") + dim(`  dashboard → ${url}   (Ctrl+C to exit)`));
}
function report(all) {
    const events = readEvents();
    const last = events[events.length - 1]?.session;
    const scoped = all ? events : events.filter((e) => e.session === last);
    printReport(buildReport(scoped), all);
}
function rules() {
    const n = (a) => a.length;
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
function parsePort(args) {
    const i = args.indexOf("--port");
    const v = i >= 0 ? Number(args[i + 1]) : NaN;
    return Number.isInteger(v) && v > 0 && v < 65536 ? v : 8787;
}
process.stdout.on("error", (e) => { if (e.code === "EPIPE")
    process.exit(0); });
const [, , cmd, ...args] = process.argv;
const flag = (f) => args.includes(f);
switch (cmd) {
    case "hook":
        await runHook();
        break;
    case "install":
        install(flag("--project"));
        break;
    case "uninstall":
        uninstall(flag("--project"));
        break;
    case "watch":
        watch();
        break;
    case "dashboard":
        await dashboard(parsePort(args));
        break;
    case "report":
        report(flag("--all"));
        break;
    case "rules":
        rules();
        break;
    case "demo":
        await demo(flag("--log"));
        break;
    default:
        console.log(HELP);
        process.exit(cmd && cmd !== "help" && cmd !== "--help" ? 1 : 0);
}
