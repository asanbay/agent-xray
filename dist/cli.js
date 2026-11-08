#!/usr/bin/env node
import fs from "node:fs";
import { runHook } from "./hook.js";
import { install, uninstall } from "./install.js";
import { demo } from "./demo.js";
import { readEvents } from "./store.js";
import { buildReport, printReport } from "./report.js";
import { bold, dim, formatEvent, sessionHeader } from "./render.js";
import { customRulesPath, eventsPath } from "./paths.js";
import { DEFAULT_RULES } from "./rules.js";
const HELP = `${bold("agent-xray")} — X-ray for AI coding agents

Usage:
  agent-xray install [--project]     add the guard hook to Claude Code (user-level, or ./.claude/settings.local.json)
  agent-xray uninstall [--project]   remove it again
  agent-xray watch                   live feed of what the agent touches (run in a second terminal)
  agent-xray report [--all]          summary + risk grade for the last session (or everything)
  agent-xray rules                   show where to customise rules
  agent-xray demo                    simulated session, handy for recording a GIF

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
    let offset = 0;
    if (fs.existsSync(file)) {
        readEvents().slice(-15).forEach(print);
        offset = fs.statSync(file).size;
    }
    let buf = "";
    setInterval(() => {
        try {
            if (!fs.existsSync(file))
                return;
            const size = fs.statSync(file).size;
            if (size < offset)
                offset = 0; // log was cleared
            if (size === offset)
                return;
            const fd = fs.openSync(file, "r");
            const chunk = Buffer.alloc(size - offset);
            fs.readSync(fd, chunk, 0, chunk.length, offset);
            fs.closeSync(fd);
            offset = size;
            buf += chunk.toString("utf8");
            const lines = buf.split("\n");
            buf = lines.pop() ?? "";
            for (const l of lines) {
                if (!l.trim())
                    continue;
                try {
                    print(JSON.parse(l));
                }
                catch { /* ignore torn line */ }
            }
        }
        catch { /* keep watching */ }
    }, 200);
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
    case "report":
        report(flag("--all"));
        break;
    case "rules":
        rules();
        break;
    case "demo":
        await demo();
        break;
    default:
        console.log(HELP);
        process.exit(cmd && cmd !== "help" && cmd !== "--help" ? 1 : 0);
}
