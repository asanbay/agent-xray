import fs from "node:fs";
import type { XrayEvent } from "./types.js";
import { errorsPath, eventsPath, xrayHome } from "./paths.js";

function ensureDir(): void {
  fs.mkdirSync(xrayHome(), { recursive: true, mode: 0o700 });
}

export function appendEvent(e: XrayEvent): void {
  ensureDir();
  fs.appendFileSync(eventsPath(), JSON.stringify(e) + "\n", { mode: 0o600 });
}

export function logError(err: unknown): void {
  try {
    ensureDir();
    const msg = err instanceof Error ? err.stack ?? err.message : String(err);
    fs.appendFileSync(errorsPath(), `${new Date().toISOString()} ${msg}\n`);
  } catch { /* nothing else we can do */ }
}

const MAX_READ = 20 * 1024 * 1024;

export function readEvents(): XrayEvent[] {
  const f = eventsPath();
  if (!fs.existsSync(f)) return [];
  const size = fs.statSync(f).size;
  let text: string;
  if (size > MAX_READ) {
    const fd = fs.openSync(f, "r");
    const buf = Buffer.alloc(MAX_READ);
    fs.readSync(fd, buf, 0, MAX_READ, size - MAX_READ);
    fs.closeSync(fd);
    text = buf.toString("utf8");
    text = text.slice(text.indexOf("\n") + 1); // drop the partial first line
  } else text = fs.readFileSync(f, "utf8");
  const out: XrayEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line) as XrayEvent); } catch { /* skip torn line */ }
  }
  return out;
}
