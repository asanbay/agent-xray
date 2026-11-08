import fs from "node:fs";
import { createHash } from "node:crypto";
import { configPath, customRulesPath, sealPath, xrayHome } from "./paths.js";
/**
 * agent-xray mode. Default is `observe`: everything is logged, nothing is denied.
 * `guard` makes warn → ask and block → deny. A human flips modes from their own
 * terminal (`agent-xray mode …`); an agent that tries gets flagged (see rules).
 */
export function loadConfig() {
    try {
        const j = JSON.parse(fs.readFileSync(configPath(), "utf8"));
        return { mode: j.mode === "guard" ? "guard" : "observe" };
    }
    catch {
        return { mode: "observe" };
    }
}
export function setMode(mode) {
    fs.mkdirSync(xrayHome(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(configPath(), JSON.stringify({ mode }, null, 2) + "\n", { mode: 0o600 });
    seal();
}
const sha = (f) => {
    try {
        return createHash("sha256").update(fs.readFileSync(f)).digest("hex");
    }
    catch {
        return "-";
    } // file does not exist (yet)
};
/**
 * Stamp a hash of config.json + rules.json. The hook re-checks it on every call:
 * if someone edits these files by hand (an agent trying to let itself through),
 * the seal no longer matches and every event is flagged as tampered.
 */
export function seal() {
    fs.mkdirSync(xrayHome(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(sealPath(), JSON.stringify({ configSha: sha(configPath()), rulesSha: sha(customRulesPath()) }, null, 2) + "\n", { mode: 0o600 });
}
export function verifySeal() {
    try {
        if (!fs.existsSync(sealPath()))
            return { ok: true, detail: "" }; // never sealed — nothing to check
        const s = JSON.parse(fs.readFileSync(sealPath(), "utf8"));
        const bad = [];
        if (s.configSha !== sha(configPath()))
            bad.push("config.json");
        if (s.rulesSha !== sha(customRulesPath()))
            bad.push("rules.json");
        return bad.length
            ? { ok: false, detail: `agent-xray ${bad.join(", ")} modified outside \`agent-xray mode\`` }
            : { ok: true, detail: "" };
    }
    catch {
        return { ok: true, detail: "" }; // a broken seal file must not brick the agent
    }
}
