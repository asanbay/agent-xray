import fs from "node:fs";
import path from "node:path";
import { rank } from "./types.js";
import { customRulesPath, home, shortPath, slashes } from "./paths.js";
const R = String.raw;
export const DEFAULT_RULES = {
    file: {
        // Checked first: explicit exceptions win over block/warn.
        allow: ["**/.env.example", "**/.env.sample", "**/.env.template", "**/*.pub"],
        block: [
            "**/.ssh", "**/.ssh/**",
            "**/.gnupg", "**/.gnupg/**",
            "**/.aws/credentials",
            "**/.config/gcloud/**",
            "**/.azure/**",
            "**/.kube/config",
            "**/.docker/config.json",
            "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*",
            "**/*.pem", "**/*.p12", "**/*.pfx", "**/*.keystore",
            "**/wallet.dat",
            "**/Library/Keychains/**",
            "**/Library/Application Support/Google/Chrome/**/Login Data",
            "**/Library/Application Support/Google/Chrome/**/Cookies",
            "**/.config/google-chrome/**/Login Data",
            "**/.config/google-chrome/**/Cookies",
            "**/.mozilla/firefox/**/logins.json",
            "**/.mozilla/firefox/**/key4.db",
            "/etc/shadow", "/etc/sudoers",
        ],
        warn: [
            "**/.env", "**/.env.*",
            "**/.npmrc", "**/.pypirc", "**/.netrc", "**/.git-credentials",
            "**/credentials.json", "**/*secret*", "**/*.kdbx",
            "**/.bash_history", "**/.zsh_history",
        ],
    },
    // Writes that give an agent persistence or let it switch off its own guardrails.
    // `block` covers agent-xray's own files and the hook installs — in guard mode
    // an agent cannot edit its way around the filter ("я чайник" rules below).
    fileWrite: {
        block: [
            "~/.agent-xray/**",
            "~/.claude/settings.json",
            "~/.zcode/cli/config.json",
            "~/.cursor/hooks.json",
        ],
        warn: [
            "**/.bashrc", "**/.zshrc", "**/.zprofile", "**/.profile", "**/.bash_profile",
            "**/.git/hooks/**",
            "**/.claude/settings.local.json",
            "**/.github/workflows/**",
            "**/Library/LaunchAgents/**", "**/.config/autostart/**",
        ],
    },
    command: {
        block: [
            { pattern: R `\brm\s+-[a-z]*[rf][a-z]*\s+(?:-[a-z]+\s+)*(?:\/|~\/?|\$HOME\/?|\/\*|~\/\*)(?:\s|$)`, reason: "recursive delete of / or home" },
            { pattern: R `\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b`, reason: "downloads and pipes straight into a shell" },
            { pattern: R `:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`, reason: "fork bomb" },
            { pattern: R `\bmkfs(?:\.\w+)?\b|\bdd\s+[^|;&\n]*\bof=/dev/`, reason: "disk-destroying command" },
            { pattern: R `\bchmod\s+(?:-R\s+)?777\s+\/(?:\s|$)`, reason: "world-writable root" },
            { pattern: R `\b(?:printenv|env)\b[^|;&\n]*\|\s*(?:curl|wget|nc|ncat)\b`, reason: "environment/secrets piped to the network" },
            { pattern: R `\bcurl\b[^|;&\n]*\s(?:-d|-F|-T|--data\S*|--form|--upload-file)\s*=?\s*@?\S*(?:\.env|id_rsa|id_ed25519|\.pem|credentials)\b`, reason: "uploads a secret file" },
            { pattern: R `\bagent-xray\s+(?:uninstall|mode|seal)\b`, reason: "tries to switch off agent-xray — 🫖 я чайник" },
            { pattern: R `cli\.js\s+(?:uninstall|mode|seal)\b`, reason: "tries to switch off agent-xray — 🫖 я чайник" },
            { pattern: R `\bnpm\s+(?:uninstall|rm)\s+(?:-g\s+)?["']?agent-xray\b`, reason: "tries to remove agent-xray — 🫖 я чайник" },
        ],
        warn: [
            { pattern: R `(?:^|[;&|]\s*)(?:printenv|env)\s*(?:$|[|;&>])`, reason: "dumps environment variables" },
            { pattern: R `\b(?:nc|ncat|netcat|socat)\b`, reason: "raw network tool" },
            { pattern: R `\bsudo\b`, reason: "privilege escalation" },
            { pattern: R `\bgit\s+push\b[^;&|\n]*(?:--force|\s-f)\b`, reason: "force push" },
            { pattern: R `\b(?:scp|sftp)\b`, reason: "remote file transfer" },
            { pattern: R `\bnpm\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b`, reason: "publishes a package" },
            { pattern: R `\b(?:chmod|chown)\s+-R\b`, reason: "recursive permission change" },
            { pattern: R `\bcrontab\b|\bsystemctl\s+(?:enable|start)\b|\blaunchctl\s+(?:load|bootstrap)\b`, reason: "installs persistence" },
            { pattern: R `\bdocker\s+run\b[^;&|\n]*(?:--privileged|-v\s+\/:)`, reason: "privileged container" },
            { pattern: R `\beval\b[^;&|\n]*\$\(\s*(?:curl|wget)`, reason: "evals downloaded code" },
        ],
    },
    network: {
        allow: [
            "anthropic.com", "claude.ai", "github.com", "githubusercontent.com",
            "npmjs.org", "npmjs.com", "yarnpkg.com", "pypi.org", "pythonhosted.org",
            "crates.io", "localhost", "127.0.0.1",
        ],
        // Classic exfiltration / tunnel / paste endpoints.
        warn: [
            "pastebin.com", "transfer.sh", "webhook.site", "requestbin.com", "pipedream.net",
            "ngrok.io", "ngrok-free.app", "ngrok.app",
            "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh",
            "burpcollaborator.net", "0x0.st", "file.io", "paste.ee", "hastebin.com",
            "api.telegram.org", "hooks.slack.com",
        ],
    },
};
/** Built-in rules + optional ~/.agent-xray/rules.json (arrays are appended). */
export function loadRules() {
    const base = JSON.parse(JSON.stringify(DEFAULT_RULES));
    try {
        const f = customRulesPath();
        if (!fs.existsSync(f))
            return base;
        const u = JSON.parse(fs.readFileSync(f, "utf8"));
        const add = (a, b) => (Array.isArray(b) ? [...a, ...b] : a);
        base.file.allow = add(base.file.allow, u?.file?.allow);
        base.file.block = add(base.file.block, u?.file?.block);
        base.file.warn = add(base.file.warn, u?.file?.warn);
        base.fileWrite.block = add(base.fileWrite.block, u?.fileWrite?.block);
        base.fileWrite.warn = add(base.fileWrite.warn, u?.fileWrite?.warn);
        base.command.block = add(base.command.block, u?.command?.block);
        base.command.warn = add(base.command.warn, u?.command?.warn);
        base.network.allow = add(base.network.allow, u?.network?.allow);
        base.network.warn = add(base.network.warn, u?.network?.warn);
    }
    catch {
        /* a broken rules.json must never break the agent */
    }
    return base;
}
// ---------- glob ----------
const cache = new Map();
export function globToRegExp(glob) {
    const hit = cache.get(glob);
    if (hit)
        return hit;
    let g = slashes(glob);
    if (g.startsWith("~/"))
        g = home() + g.slice(1);
    let re = "^";
    for (let i = 0; i < g.length; i++) {
        const c = g[i];
        if (c === "*") {
            if (g[i + 1] === "*") {
                if (g[i + 2] === "/") {
                    re += "(?:.*/)?";
                    i += 2;
                }
                else {
                    re += ".*";
                    i += 1;
                }
            }
            else
                re += "[^/]*";
        }
        else if (c === "?")
            re += "[^/]";
        else
            re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
    const rx = new RegExp(re + "$", "i");
    cache.set(glob, rx);
    return rx;
}
// ---------- files ----------
function expandVars(t) {
    const h = home();
    return t
        .replace(/^~(?=\/|$)/, h)
        .replace(/^\$\{?HOME\}?(?=\/|$)/, h);
}
export function resolvePath(target, cwd) {
    const t = expandVars(slashes(target));
    return slashes(path.resolve(slashes(cwd), t));
}
function matchFile(p, op, rules) {
    const variants = [p, p.endsWith("/") ? p : p + "/"]; // so "~/.ssh" matches "~/.ssh/**"
    const test = (list) => list.find((g) => variants.some((v) => globToRegExp(g).test(v)));
    const a = test(rules.file.allow);
    if (a)
        return { level: "allow", rule: a };
    const b = test(rules.file.block);
    if (b)
        return { level: "block", rule: b, reason: `sensitive path (${b})` };
    const w = test(rules.file.warn);
    if (w)
        return { level: "warn", rule: w, reason: `sensitive path (${w})` };
    if (op === "write") {
        const wb = test(rules.fileWrite.block);
        if (wb)
            return { level: "block", rule: wb, reason: `guardrail write (${wb}) — 🫖 я чайник` };
        const ww = test(rules.fileWrite.warn);
        if (ww)
            return { level: "warn", rule: ww, reason: `persistence/config write (${ww})` };
    }
    return { level: "allow" };
}
export function evaluateFile(target, cwd, op, rules) {
    const abs = resolvePath(target, cwd);
    const candidates = [abs];
    try {
        // a harmless-looking symlink may point at ~/.ssh/id_rsa
        const real = slashes(fs.realpathSync(abs));
        if (real !== abs)
            candidates.push(real);
    }
    catch { /* file may not exist yet */ }
    let worst = { level: "allow" };
    for (const c of candidates) {
        const v = matchFile(c, op, rules);
        if (rank(v.level) > rank(worst.level))
            worst = v;
    }
    return { ...worst, path: abs };
}
// ---------- network ----------
const hostIn = (host, list) => list.some((h) => host === h || host.endsWith("." + h));
export function evaluateHost(host, upload, rules) {
    const h = host.toLowerCase();
    if (hostIn(h, rules.network.allow))
        return { level: "allow", rule: "network.allow" };
    if (hostIn(h, rules.network.warn))
        return { level: "warn", reason: `exfiltration-prone host (${h})`, rule: "network.warn" };
    if (upload)
        return { level: "warn", reason: `uploads data to unlisted host (${h})`, rule: "upload" };
    return { level: "allow", reason: "unlisted host" };
}
// ---------- shell commands ----------
export function tokenize(cmd) {
    const out = [];
    let cur = "";
    let q = null;
    for (let i = 0; i < cmd.length; i++) {
        const c = cmd[i];
        if (q) {
            if (c === q)
                q = null;
            else if (c === "\\" && q === '"' && i + 1 < cmd.length)
                cur += cmd[++i];
            else
                cur += c;
            continue;
        }
        if (c === "'" || c === '"') {
            q = c;
            continue;
        }
        if (c === "\\" && i + 1 < cmd.length) {
            cur += cmd[++i];
            continue;
        }
        if (/\s/.test(c) || ";|&()<>`".includes(c)) {
            if (cur) {
                out.push(cur);
                cur = "";
            }
            continue;
        }
        cur += c;
    }
    if (cur)
        out.push(cur);
    return out;
}
const BARE = /^(?:id_(?:rsa|ed25519|ecdsa|dsa)|credentials|shadow|authorized_keys|wallet\.dat)$/i;
const pathLike = (t) => t.includes("/") || t.startsWith("~") || t.startsWith(".") || t.startsWith("$HOME") ||
    /\.[a-z0-9]{1,8}$/i.test(t) || BARE.test(t);
export function evaluateCommand(cmd, cwd, rules) {
    const findings = [];
    for (const r of rules.command.block)
        if (safeRx(r.pattern).test(cmd))
            findings.push({ level: "block", reason: r.reason, rule: r.pattern });
    for (const r of rules.command.warn)
        if (safeRx(r.pattern).test(cmd))
            findings.push({ level: "warn", reason: r.reason, rule: r.pattern });
    const writeish = /(?:>|\btee\b|\bsed\s+-i|\bmv\b|\bcp\b|\bln\b)/.test(cmd);
    const upload = /\bcurl\b[^|;&\n]*\s(?:-d|-F|-T|--data\S*|--form|--upload-file|-X\s*(?:POST|PUT|PATCH))(?:\s|=|$)/i.test(cmd) ||
        /\bwget\b[^|;&\n]*--post-(?:data|file)/i.test(cmd);
    const hosts = new Map();
    const seen = new Set();
    for (const tok of tokenize(cmd)) {
        const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#@]*@)?([^\/:?#]+)/i.exec(tok);
        if (url) {
            const h = url[1].toLowerCase();
            if (!hosts.has(h))
                hosts.set(h, evaluateHost(h, upload, rules));
            continue;
        }
        const pieces = tok.includes("=") ? [tok, tok.slice(tok.indexOf("=") + 1)] : [tok];
        for (const piece of pieces) {
            if (!piece || piece.startsWith("-") || !pathLike(piece))
                continue;
            for (const op of writeish ? ["read", "write"] : ["read"]) {
                const v = evaluateFile(piece, cwd, op, rules);
                if (v.level === "allow")
                    continue;
                const reason = `${shortPath(v.path)}: ${v.reason}`;
                if (seen.has(reason))
                    continue;
                seen.add(reason);
                findings.push({ level: v.level, reason, rule: v.rule });
            }
        }
    }
    return { findings, hosts: [...hosts].map(([host, verdict]) => ({ host, verdict })) };
}
function safeRx(p) {
    try {
        return new RegExp(p, "i");
    }
    catch {
        return /$^/;
    }
}
export function worst(vs) {
    let w = { level: "allow" };
    for (const v of vs)
        if (rank(v.level) > rank(w.level))
            w = v;
    return w;
}
