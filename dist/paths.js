import os from "node:os";
import path from "node:path";
export const slashes = (p) => p.replace(/\\/g, "/");
export const home = () => slashes(os.homedir());
/** Where agent-xray keeps its log and optional rules.json. */
export const xrayHome = () => process.env.AGENT_XRAY_HOME || path.join(os.homedir(), ".agent-xray");
export const eventsPath = () => path.join(xrayHome(), "events.jsonl");
export const errorsPath = () => path.join(xrayHome(), "errors.log");
export const customRulesPath = () => path.join(xrayHome(), "rules.json");
/** Replace the home directory with ~ for display. */
export function shortPath(p) {
    const q = slashes(p);
    const h = home();
    if (q === h)
        return "~";
    if (q.startsWith(h + "/"))
        return "~" + q.slice(h.length);
    return q;
}
