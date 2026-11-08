import http from "node:http";
import { readEvents, followEvents } from "./store.js";
import { buildReport } from "./report.js";
import { eventsPath } from "./paths.js";
const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-xray</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; }
  body { background:#0b0f14; color:#d7dde6; font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; padding:20px; }
  header { display:flex; align-items:center; gap:16px; flex-wrap:wrap; margin-bottom:16px; }
  h1 { font-size:18px; letter-spacing:.4px; }
  h1 span { color:#7aa2f7; }
  .live { display:inline-flex; align-items:center; gap:6px; color:#8b98a9; font-size:12px; }
  .live i { width:8px; height:8px; border-radius:50%; background:#4ade80; animation:pulse 1.6s infinite; }
  @keyframes pulse { 50% { opacity:.25; } }
  select { background:#131a23; color:#d7dde6; border:1px solid #223041; border-radius:6px; padding:5px 8px; font:inherit; max-width:340px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(118px,1fr)); gap:10px; margin-bottom:14px; }
  .card { background:#111823; border:1px solid #1d2836; border-radius:10px; padding:11px 14px; }
  .card b { display:block; font-size:21px; }
  .card small { color:#8b98a9; }
  .grade { font-size:32px; }
  .ok { color:#4ade80; } .warn { color:#fbbf24; } .block { color:#f87171; }
  .chips { margin-bottom:10px; display:flex; gap:8px; }
  .chip { cursor:pointer; border:1px solid #223041; background:#131a23; color:#8b98a9; border-radius:999px; padding:3px 12px; font:inherit; font-size:12px; }
  .chip.on { color:#e8edf4; border-color:#3b82f6; background:#16233a; }
  .feed { background:#0e141c; border:1px solid #1d2836; border-radius:10px; padding:6px 0; max-height:70vh; overflow-y:auto; }
  .row { display:flex; gap:10px; padding:4px 14px; word-break:break-all; }
  .row:hover { background:#131a23; }
  .t { color:#5c6b7f; flex:none; }
  .lv { flex:none; width:66px; font-weight:700; }
  .k { color:#7aa2f7; flex:none; width:92px; }
  .why { color:#8b98a9; }
  .empty { color:#8b98a9; text-align:center; padding:44px 0; }
  footer { margin-top:12px; color:#5c6b7f; font-size:12px; }
</style>
</head>
<body>
<header>
  <h1>agent<span>-xray</span></h1>
  <span class="live"><i></i>live</span>
  <select id="session"></select>
</header>
<div class="cards" id="cards"></div>
<div class="chips">
  <button class="chip on" data-f="all">all</button>
  <button class="chip" data-f="warn">⚠ warned</button>
  <button class="chip" data-f="block">✖ blocked</button>
</div>
<div class="feed" id="feed"><div class="empty">loading…</div></div>
<footer>log: <span id="logpath"></span> · events never contain file contents</footer>
<script>
"use strict";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const fmtTime = (ts) => new Date(ts).toTimeString().slice(0, 8);
let session = "";          // "" = last session, "all", or a session id
let filter = "all";
let es = null, timer = null;

const chip = (lv) => lv === "block" ? '<span class="lv block">✖ BLOCK</span>'
  : lv === "warn" ? '<span class="lv warn">⚠ WARN</span>' : '<span class="lv ok">✔ ok</span>';

function rowHTML(e) {
  const k = e.kind === "file" ? "file:" + e.op : e.kind === "network" ? "net" : "exec";
  const why = e.reason && e.level !== "allow" ? ' <span class="why">← ' + esc(e.reason) + "</span>" : "";
  return '<div class="row"><span class="t">' + fmtTime(e.ts) + "</span>" + chip(e.level)
    + '<span class="k">' + k + "</span><span>" + esc(e.target) + why + "</span></div>";
}

function card(n, label, cls) {
  return '<div class="card"><b class="' + (cls || "") + '">' + n + "</b><small>" + label + "</small></div>";
}

function render(events, report) {
  const shown = events.filter((e) =>
    filter === "all" ? true : filter === "block" ? e.level === "block" : e.level === "warn");
  const feed = $("feed");
  const stick = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 40;
  feed.innerHTML = shown.length
    ? shown.map(rowHTML).join("")
    : '<div class="empty">' + (events.length ? "nothing matches this filter" : "no events yet — run <b>agent-xray demo --log</b> or use your agent") + "</div>";
  if (stick) feed.scrollTop = feed.scrollHeight;
  const g = report.grade, gc = (g === "A" || g === "B") ? "ok" : g === "C" ? "warn" : "block";
  $("cards").innerHTML =
    card(g, "risk grade " + report.score + "/100", "grade " + gc)
    + card(report.filesRead, "files read")
    + card(report.filesWritten, "files written")
    + card(report.commands, "commands")
    + card(report.hosts.length, "hosts")
    + card(report.warned.length, "warned", "warn")
    + card(report.blocked.length, "blocked", "block");
}

async function load() {
  const r = await fetch("/api/events?session=" + encodeURIComponent(session));
  const { events, report } = await r.json();
  render(events, report);
  await loadSessions();
}

async function loadSessions() {
  const list = await (await fetch("/api/sessions")).json();
  const sel = $("session");
  const cur = session;
  sel.innerHTML = '<option value="">last session</option><option value="all">all sessions</option>'
    + list.map((s) => '<option value="' + esc(s.session) + '">' + esc(s.session.slice(0, 8)) + " · " + s.count + "</option>").join("");
  sel.value = [...sel.options].some((o) => o.value === cur) ? cur : "";
  if (sel.value !== cur) { session = sel.value; }
}

function connect() {
  if (es) es.close();
  es = new EventSource("/api/stream");
  es.onmessage = () => { clearTimeout(timer); timer = setTimeout(load, 150); };
}

$("session").addEventListener("change", (ev) => { session = ev.target.value; load(); });
document.querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".chip").forEach((x) => x.classList.remove("on"));
  b.classList.add("on");
  filter = b.dataset.f;
  load();
}));
$("logpath").textContent = "__LOGPATH__";
load();
connect();
</script>
</body>
</html>`;
export function startDashboard(opts = {}) {
    const wanted = opts.port ?? 8787;
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            try {
                route(req, res);
            }
            catch {
                try {
                    res.writeHead(500);
                    res.end();
                }
                catch { /* socket gone */ }
            }
        });
        server.on("error", reject);
        server.listen(wanted, "127.0.0.1", () => {
            const a = server.address();
            const port = typeof a === "object" && a ? a.port : wanted;
            resolve({ url: `http://127.0.0.1:${port}`, port, server });
        });
    });
}
function route(req, res) {
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    if (u.pathname === "/") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(PAGE.replace("__LOGPATH__", eventsPath()));
        return;
    }
    if (u.pathname === "/api/sessions") {
        json(res, sessionSummary(readEvents()));
        return;
    }
    if (u.pathname === "/api/events") {
        const scoped = scope(readEvents(), u.searchParams.get("session"));
        json(res, { events: scoped, report: buildReport(scoped) });
        return;
    }
    if (u.pathname === "/api/stream") {
        stream(res);
        return;
    }
    res.writeHead(404);
    res.end();
}
/** "" = last session, "all" = everything, otherwise an exact session id. */
function scope(events, session) {
    if (session === "all")
        return events;
    const last = session || events[events.length - 1]?.session;
    return last ? events.filter((e) => e.session === last) : [];
}
function sessionSummary(events) {
    const m = new Map();
    for (const e of events) {
        const s = m.get(e.session) ?? { session: e.session, count: 0, from: e.ts, to: e.ts };
        s.count++;
        s.to = e.ts;
        m.set(e.session, s);
    }
    return [...m.values()];
}
function stream(res) {
    res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store",
        "connection": "keep-alive",
    });
    res.write(": connected\n\n");
    const stop = followEvents((e) => {
        try {
            res.write("data: " + JSON.stringify(e) + "\n\n");
        }
        catch { /* client went away; 'close' cleans up */ }
    });
    const ping = setInterval(() => {
        try {
            res.write(": ping\n\n");
        }
        catch { /* same as above */ }
    }, 15000);
    res.on("close", () => { clearInterval(ping); stop(); });
}
function json(res, body) {
    res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
}
