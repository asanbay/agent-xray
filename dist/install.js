import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const MARK = "--xray"; // marks hook commands that belong to us
const MATCHER = "Read|Edit|Write|MultiEdit|NotebookEdit|Bash|WebFetch|Grep|Glob";
function settingsPath(project) {
    if (project)
        return path.join(process.cwd(), ".claude", "settings.local.json");
    const dir = process.env.CLAUDE_CONFIG_DIR || path.join(os.homedir(), ".claude");
    return path.join(dir, "settings.json");
}
function load(file) {
    if (!fs.existsSync(file))
        return {};
    const text = fs.readFileSync(file, "utf8");
    if (!text.trim())
        return {};
    try {
        return JSON.parse(text);
    }
    catch {
        throw new Error(`${file} is not valid JSON — refusing to touch it.`);
    }
}
function stripOurs(settings) {
    const arr = settings.hooks?.PreToolUse;
    if (!Array.isArray(arr))
        return 0;
    let removed = 0;
    for (const group of arr) {
        if (!Array.isArray(group.hooks))
            continue;
        const before = group.hooks.length;
        group.hooks = group.hooks.filter((h) => !(typeof h?.command === "string" && h.command.includes(MARK)));
        removed += before - group.hooks.length;
    }
    settings.hooks.PreToolUse = arr.filter((g) => Array.isArray(g.hooks) && g.hooks.length > 0);
    if (settings.hooks.PreToolUse.length === 0)
        delete settings.hooks.PreToolUse;
    if (Object.keys(settings.hooks).length === 0)
        delete settings.hooks;
    return removed;
}
function save(file, settings) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(settings, null, 2) + "\n");
}
export function install(project) {
    const file = settingsPath(project);
    const settings = load(file);
    if (fs.existsSync(file)) {
        const backup = file + ".xray-backup";
        if (!fs.existsSync(backup))
            fs.copyFileSync(file, backup);
    }
    stripOurs(settings);
    const script = fs.realpathSync(process.argv[1]);
    const command = `"${process.execPath}" "${script}" hook ${MARK}`;
    settings.hooks ??= {};
    settings.hooks.PreToolUse ??= [];
    settings.hooks.PreToolUse.push({ matcher: MATCHER, hooks: [{ type: "command", command, timeout: 10 }] });
    save(file, settings);
    console.log(`✔ Hook installed in ${file}`);
    if (script.includes("_npx"))
        console.log("⚠ You are running from the npx cache; it may be cleaned up. For a permanent install: npm i -g agent-xray, then re-run `agent-xray install`.");
    console.log("\nNext:\n  1. Restart Claude Code (hooks are read at startup).\n  2. In another terminal run:  agent-xray watch\n  3. Use your agent as usual.");
}
export function uninstall(project) {
    const file = settingsPath(project);
    if (!fs.existsSync(file)) {
        console.log(`Nothing to do: ${file} does not exist.`);
        return;
    }
    const settings = load(file);
    const n = stripOurs(settings);
    save(file, settings);
    console.log(n ? `✔ Removed agent-xray hook from ${file}` : `No agent-xray hook found in ${file}`);
}
