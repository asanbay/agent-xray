import os from "node:os";
import path from "node:path";

export const slashes = (p: string): string => p.replace(/\\/g, "/");
export const home = (): string => slashes(os.homedir());

/** Where agent-xray keeps its log and optional rules.json. */
export const xrayHome = (): string =>
  process.env.AGENT_XRAY_HOME || path.join(os.homedir(), ".agent-xray");
export const eventsPath = (): string => path.join(xrayHome(), "events.jsonl");
export const errorsPath = (): string => path.join(xrayHome(), "errors.log");
export const customRulesPath = (): string => path.join(xrayHome(), "rules.json");
export const configPath = (): string => path.join(xrayHome(), "config.json");
export const sealPath = (): string => path.join(xrayHome(), "seal.json");

/** Replace the home directory with ~ for display. */
export function shortPath(p: string): string {
  const q = slashes(p);
  const h = home();
  if (q === h) return "~";
  if (q.startsWith(h + "/")) return "~" + q.slice(h.length);
  return q;
}
