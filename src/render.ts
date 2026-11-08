import type { XrayEvent } from "./types.js";

const paint = (code: number) => (s: string): string => {
  if (process.env.NO_COLOR) return s;
  if (!process.stdout.isTTY && !process.env.FORCE_COLOR) return s;
  return `\x1b[${code}m${s}\x1b[0m`;
};
export const bold = paint(1);
export const dim = paint(2);
export const red = paint(31);
export const green = paint(32);
export const yellow = paint(33);
export const cyan = paint(36);

export const clock = (ts: number): string => new Date(ts).toTimeString().slice(0, 8);

const label = (e: XrayEvent): string =>
  e.kind === "file" ? `file:${e.op}` : e.kind === "network" ? "net" : "exec";

const clip = (s: string, n = 110): string => (s.length > n ? s.slice(0, n - 1) + "…" : s);

export function formatEvent(e: XrayEvent): string {
  const icon =
    e.level === "block" ? red("✖ BLOCK") : e.level === "warn" ? yellow("⚠ WARN ") : green("✔ ok   ");
  const tint = e.level === "block" ? red : e.level === "warn" ? yellow : (s: string) => s;
  const reason = e.reason && e.level !== "allow" ? "  " + dim("← " + e.reason) : "";
  return `${dim(clock(e.ts))}  ${icon}  ${cyan(label(e).padEnd(10))} ${tint(clip(e.target))}${reason}`;
}

export function sessionHeader(id: string): string {
  return dim(`── session ${id.slice(0, 8)} ${"─".repeat(40)}`);
}
