import fs from "node:fs";
import { errorsPath, eventsPath, xrayHome } from "./paths.js";
function ensureDir() {
    fs.mkdirSync(xrayHome(), { recursive: true, mode: 0o700 });
}
export function appendEvent(e) {
    ensureDir();
    fs.appendFileSync(eventsPath(), JSON.stringify(e) + "\n", { mode: 0o600 });
}
export function logError(err) {
    try {
        ensureDir();
        const msg = err instanceof Error ? err.stack ?? err.message : String(err);
        fs.appendFileSync(errorsPath(), `${new Date().toISOString()} ${msg}\n`);
    }
    catch { /* nothing else we can do */ }
}
const MAX_READ = 20 * 1024 * 1024;
export function readEvents() {
    const f = eventsPath();
    if (!fs.existsSync(f))
        return [];
    const size = fs.statSync(f).size;
    let text;
    if (size > MAX_READ) {
        const fd = fs.openSync(f, "r");
        const buf = Buffer.alloc(MAX_READ);
        fs.readSync(fd, buf, 0, MAX_READ, size - MAX_READ);
        fs.closeSync(fd);
        text = buf.toString("utf8");
        text = text.slice(text.indexOf("\n") + 1); // drop the partial first line
    }
    else
        text = fs.readFileSync(f, "utf8");
    const out = [];
    for (const line of text.split("\n")) {
        if (!line.trim())
            continue;
        try {
            out.push(JSON.parse(line));
        }
        catch { /* skip torn line */ }
    }
    return out;
}
/**
 * Tail events.jsonl and call onEvent for every new event.
 * Returns a stop function. Used by `watch` and the dashboard stream.
 */
export function followEvents(onEvent, intervalMs = 250) {
    const f = eventsPath();
    let offset = fs.existsSync(f) ? fs.statSync(f).size : 0;
    let buf = "";
    const timer = setInterval(() => {
        try {
            if (!fs.existsSync(f))
                return;
            const size = fs.statSync(f).size;
            if (size < offset)
                offset = 0; // log was cleared
            if (size === offset)
                return;
            const fd = fs.openSync(f, "r");
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
                    onEvent(JSON.parse(l));
                }
                catch { /* ignore torn line */ }
            }
        }
        catch { /* keep following */ }
    }, intervalMs);
    return () => clearInterval(timer);
}
