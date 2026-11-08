import http from "node:http";
import type { XrayEvent } from "./types.js";
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
  .chips { margin-bottom:10px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .chip { cursor:pointer; border:1px solid #223041; background:#131a23; color:#8b98a9; border-radius:999px; padding:3px 12px; font:inherit; font-size:12px; }
  .chip.on { color:#e8edf4; border-color:#3b82f6; background:#16233a; }
  .sep { width:1px; height:18px; background:#223041; margin:0 4px; }
  .feed { background:#0e141c; border:1px solid #1d2836; border-radius:10px; padding:6px 0; height:66vh; overflow-y:auto; }
  .row { display:flex; gap:10px; padding:4px 14px; word-break:break-all; }
  .row:hover { background:#131a23; }
  .t { color:#5c6b7f; flex:none; }
  .lv { flex:none; width:66px; font-weight:700; }
  .k { color:#7aa2f7; flex:none; width:92px; }
  .why { color:#8b98a9; }
  .empty { color:#8b98a9; text-align:center; padding:44px 0; }
  .stage { position:relative; height:66vh; background:radial-gradient(ellipse at 50% 42%, #101a29 0%, #0b0f14 62%); border:1px solid #1d2836; border-radius:10px; overflow:hidden; }
  .stage canvas { width:100%; height:100%; display:block; cursor:grab; }
  .stage canvas:active { cursor:grabbing; }
  .tip { position:absolute; pointer-events:none; background:#131a23ee; border:1px solid #223041; border-radius:8px; padding:8px 10px; font-size:12px; max-width:420px; word-break:break-all; display:none; z-index:5; }
  .tip b { color:#e8edf4; } .tip small { color:#8b98a9; }
  .hint { position:absolute; right:12px; bottom:10px; color:#3d4a5c; font-size:11px; }
  .legend { position:absolute; left:12px; bottom:10px; color:#8b98a9; font-size:11px; }
  .legend i { font-style:normal; }
  .legend b { font-weight:400; color:#5c6b7f; }
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
  <button class="chip on" data-v="feed">≡ feed</button>
  <button class="chip" data-v="universe">✦ universe</button>
  <span class="sep"></span>
  <button class="chip on" data-f="all">all</button>
  <button class="chip" data-f="warn">⚠ warned</button>
  <button class="chip" data-f="block">✖ blocked</button>
</div>
<div class="stage" id="stage" style="display:none">
  <canvas id="cv"></canvas>
  <div class="tip" id="tip"></div>
  <div class="legend"><i class="ok">●</i> ok &nbsp;<i class="warn">●</i> warn &nbsp;<i class="block">●</i> blocked &nbsp;<b>· shells: worse = closer to the agent · sectors: files / commands / network</b></div>
  <div class="hint">drag to rotate · scroll to zoom</div>
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
let view = "feed";
let es = null, timer = null;
const state = { events: [], report: null };

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

const matchFilter = (lv) =>
  filter === "all" ? true : filter === "block" ? lv === "block" : lv === "warn";

function render(events, report) {
  const shown = events.filter((e) => matchFilter(e.level));
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
  const data = await r.json();
  state.events = data.events;
  state.report = data.report;
  render(state.events, state.report);
  feedUniverse(state.events);
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

// ================= universe (3D canvas) =================
const COLOR = { ok: "#4ade80", warn: "#fbbf24", block: "#f87171", agent: "#7aa2f7" };
const RANK = { allow: 0, warn: 1, block: 2 };
const uni = {
  nodes: new Map(), pulses: [], lastTs: 0,
  ry: 0.6, rx: -0.32, zoom: 1, vy: 0.0035,
  dragging: false, lx: 0, ly: 0, idle: 0, flash: 0, hover: null,
};

function resetUniverse() {
  uni.nodes.clear(); uni.pulses.length = 0; uni.lastTs = 0; uni.flash = 0;
}

function nodeKey(e) { return e.kind + "|" + e.target; }

function layoutUniverse() {
  // Systematic layout: three kind-wedges around the agent (files left, commands
  // right, network behind); inside a wedge, severity decides the shell radius —
  // blocked actions orbit closest to the agent, allowed ones on the rim.
  const groups = { file: [], command: [], network: [] };
  for (const n of uni.nodes.values()) (groups[n.kind] || groups.file).push(n);
  const R = 300;
  const shell = { block: 0.55, warn: 0.82, allow: 1.1 };
  const kindK = { file: 1.0, command: 1.08, network: 1.18 };
  const wedge = { file: [-0.888, -0.333], command: [-0.222, 0.333], network: [0.444, 1.0] }; // × π
  const order = { block: 0, warn: 1, allow: 2 };
  for (const kind of ["file", "command", "network"]) {
    const list = groups[kind].sort((a, b) =>
      order[a.level] - order[b.level] || (a.target < b.target ? -1 : 1));
    const [t0, t1] = wedge[kind];
    const N = list.length;
    list.forEach((n, i) => {
      const th = Math.PI * (t0 + (t1 - t0) * ((i + 0.5) / Math.max(1, N)));
      const r = R * kindK[kind] * shell[n.level];
      n.x = r * Math.cos(th);
      n.z = r * Math.sin(th);
      n.y = Math.sin(i * 2.399) * (55 + 45 * shell[n.level]); // golden-angle zigzag
    });
  }
}

function feedUniverse(events) {
  let changed = false;
  for (const e of events) {
    if (e.ts <= uni.lastTs && uni.lastTs !== 0) continue;
    uni.lastTs = Math.max(uni.lastTs, e.ts);
    if (!matchFilter(e.level)) continue;
    const key = nodeKey(e);
    let n = uni.nodes.get(key);
    if (!n) {
      // born/hit live on the performance.now() clock, not the event ts clock
      const now = performance.now();
      n = { key, kind: e.kind, target: e.target, level: e.level, count: 0, born: now, hit: now, x: 0, y: 0, z: 0 };
      uni.nodes.set(key, n);
      changed = true;
    }
    if (RANK[e.level] > RANK[n.level]) n.level = e.level;
    n.count++;
    n.hit = performance.now();
    const towardAgent = e.level !== "allow";
    uni.pulses.push({
      node: n, t0: performance.now(), dur: 750 + Math.random() * 250,
      inward: towardAgent, color: COLOR[e.level] || COLOR.ok,
    });
    if (e.level === "block") uni.flash = 1;
  }
  if (changed) layoutUniverse();
}

function project(x, y, z, w, h) {
  const cosY = Math.cos(uni.ry), sinY = Math.sin(uni.ry);
  let px = x * cosY - z * sinY;
  let pz = x * sinY + z * cosY;
  const cosX = Math.cos(uni.rx), sinX = Math.sin(uni.rx);
  let py = y * cosX - pz * sinX;
  pz = y * sinX + pz * cosX;
  const f = 850 * uni.zoom;
  const s = f / (f + pz + 620);
  return { x: w / 2 + px * s, y: h / 2 + py * s, s, z: pz };
}

function drawUniverse(now) {
  const cv = $("cv"), ctx = cv.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== w * dpr || cv.height !== h * dpr) { cv.width = w * dpr; cv.height = h * dpr; }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  if (!uni.dragging && now - uni.idle > 2500) uni.ry += uni.vy;
  if (uni.flash > 0) uni.flash = Math.max(0, uni.flash - 0.03);

  const items = [];
  for (const n of uni.nodes.values()) {
    const p = project(n.x, n.y, n.z, w, h);
    items.push({ n, p });
  }
  items.sort((a, b) => a.p.z - b.p.z);

  // orbit rings at the severity shells for a depth cue
  ctx.strokeStyle = "rgba(122,162,247,0.07)";
  ctx.lineWidth = 1;
  for (const shell of [0.55, 0.82, 1.1]) {
    ctx.beginPath();
    for (let a = 0; a <= 64; a++) {
      const t = (a / 64) * Math.PI * 2;
      const q = project(330 * shell * Math.cos(t), 0, 330 * shell * Math.sin(t), w, h);
      if (a === 0) ctx.moveTo(q.x, q.y); else ctx.lineTo(q.x, q.y);
    }
    ctx.stroke();
  }

  // pulses under nodes
  uni.pulses = uni.pulses.filter((pu) => {
    const t = (now - pu.t0) / pu.dur;
    if (t >= 1) return false;
    const n = pu.node;
    const fp = project(n.x, n.y, n.z, w, h);
    const cp = project(0, 0, 0, w, h);
    const a = pu.inward ? fp : cp, b = pu.inward ? cp : fp;
    const q = { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t, s: a.s + (b.s - a.s) * t };
    for (const dt of [0, 0.06, 0.12]) {
      const tt = Math.max(0, t - dt);
      const qx = a.x + (b.x - a.x) * tt, qy = a.y + (b.y - a.y) * tt;
      const rad = 3.2 * q.s * (1 - dt * 2.2);
      if (rad <= 0) continue;
      ctx.globalAlpha = (1 - dt) * 0.9;
      ctx.fillStyle = pu.color;
      ctx.shadowColor = pu.color; ctx.shadowBlur = 12;
      ctx.beginPath(); ctx.arc(qx, qy, rad, 0, 7); ctx.fill();
    }
    ctx.globalAlpha = 1; ctx.shadowBlur = 0;
    return true;
  });

  // nodes
  let hovered = null, hd = 1e9;
  uni.hover = uni.hover || { x: -1e4, y: -1e4 };
  for (const { n, p } of items) {
    if (!matchFilter(n.level)) continue;
    const age = Math.max(0.4, 1.4 - (now - n.hit) / 90000);
    const base = n.kind === "network" ? 6 : n.kind === "command" ? 5 : 4;
    const rad = Math.max(1.2, base * p.s * age * 1.9 * (n.level === "block" ? 1.5 : 1));
    const c = COLOR[n.level] || COLOR.ok;
    ctx.shadowColor = c; ctx.shadowBlur = n.level === "allow" ? 6 : 18;
    ctx.fillStyle = c;
    ctx.globalAlpha = Math.min(1, 0.35 + age * 0.6);
    ctx.beginPath(); ctx.arc(p.x, p.y, rad, 0, 7); ctx.fill();
    ctx.shadowBlur = 0; ctx.globalAlpha = 1;
    if (n.level !== "allow" && p.s > 0.55) {
      ctx.fillStyle = "rgba(139,152,169,0.85)";
      ctx.font = "10px ui-monospace,Menlo,monospace";
      ctx.fillText(short(n.target), p.x + rad + 4, p.y + 3);
    }
    const d = Math.hypot(uni.hover.x - p.x, uni.hover.y - p.y);
    if (d < Math.max(14, rad + 8) && d < hd) { hd = d; hovered = { n, p, rad }; }
  }

  // agent in the center
  const cp = project(0, 0, 0, w, h);
  const agentPulse = 8 + Math.sin(now / 300) * 1.5;
  ctx.shadowColor = COLOR.agent; ctx.shadowBlur = 26;
  ctx.fillStyle = COLOR.agent;
  ctx.beginPath(); ctx.arc(cp.x, cp.y, agentPulse * cp.s, 0, 7); ctx.fill();
  ctx.shadowBlur = 0;
  ctx.fillStyle = "rgba(232,237,244,0.9)";
  ctx.font = "bold 11px ui-monospace,Menlo,monospace";
  ctx.fillText("agent", cp.x + 13, cp.y - 10);

  // block flash — red vignette
  if (uni.flash > 0) {
    const g = ctx.createRadialGradient(w / 2, h / 2, Math.min(w, h) * 0.3, w / 2, h / 2, Math.max(w, h) * 0.72);
    g.addColorStop(0, "rgba(248,113,113,0)");
    g.addColorStop(1, "rgba(248,113,113," + (0.22 * uni.flash).toFixed(3) + ")");
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
  }

  // tooltip
  const tip = $("tip");
  if (hovered) {
    const n = hovered.n;
    tip.style.display = "block";
    tip.style.left = Math.min(hovered.p.x + 14, w - 260) + "px";
    tip.style.top = (hovered.p.y + 14) + "px";
    tip.innerHTML = "<b>" + esc(short(n.target)) + "</b><br><small>" + n.kind + " · " + n.level
      + " · " + n.count + "×</small>";
  } else tip.style.display = "none";
}

const short = (s) => s.length > 46 ? s.slice(0, 45) + "…" : s;

function universeLoop(now) {
  if (view === "universe") drawUniverse(now);
  requestAnimationFrame(universeLoop);
}
requestAnimationFrame(universeLoop);

// universe controls
const cv = $("cv");
cv.addEventListener("mousedown", (e) => { uni.dragging = true; uni.lx = e.clientX; uni.ly = e.clientY; });
window.addEventListener("mouseup", () => (uni.dragging = false));
window.addEventListener("mousemove", (e) => {
  const r = cv.getBoundingClientRect();
  uni.hover = { x: e.clientX - r.left, y: e.clientY - r.top };
  if (!uni.dragging) return;
  uni.ry += (e.clientX - uni.lx) * 0.006;
  uni.rx = Math.max(-1.2, Math.min(1.2, uni.rx + (e.clientY - uni.ly) * 0.005));
  uni.lx = e.clientX; uni.ly = e.clientY;
  uni.idle = performance.now();
});
cv.addEventListener("wheel", (e) => {
  e.preventDefault();
  uni.zoom = Math.max(0.55, Math.min(2.2, uni.zoom * (e.deltaY > 0 ? 0.92 : 1.08)));
}, { passive: false });

function setView(v) {
  view = v;
  $("stage").style.display = v === "universe" ? "" : "none";
  $("feed").style.display = v === "feed" ? "" : "none";
  document.querySelectorAll("[data-v]").forEach((b) => b.classList.toggle("on", b.dataset.v === v));
  if (v === "universe") { uni.lastTs = 0; feedUniverse(state.events); }
}

// ---- wiring ----
$("session").addEventListener("change", (ev) => {
  session = ev.target.value;
  resetUniverse();
  load();
});
document.querySelectorAll("[data-v]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.v)));
document.querySelectorAll("[data-f]").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("[data-f]").forEach((x) => x.classList.remove("on"));
  b.classList.add("on");
  filter = b.dataset.f;
  resetUniverse();
  load();
}));
$("logpath").textContent = "__LOGPATH__";
load();
connect();
</script>
</body>
</html>`;

export interface DashboardHandle {
  url: string;
  port: number;
  server: http.Server;
}

export function startDashboard(opts: { port?: number; open?: boolean } = {}): Promise<DashboardHandle> {
  const wanted = opts.port ?? 8787;
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try { route(req, res); }
      catch { try { res.writeHead(500); res.end(); } catch { /* socket gone */ } }
    });
    server.on("error", reject);
    server.listen(wanted, "127.0.0.1", () => {
      const a = server.address();
      const port = typeof a === "object" && a ? a.port : wanted;
      resolve({ url: `http://127.0.0.1:${port}`, port, server });
    });
  });
}

function route(req: http.IncomingMessage, res: http.ServerResponse): void {
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
  if (u.pathname === "/api/stream") { stream(res); return; }
  res.writeHead(404);
  res.end();
}

/** "" = last session, "all" = everything, otherwise an exact session id. */
function scope(events: XrayEvent[], session: string | null): XrayEvent[] {
  if (session === "all") return events;
  const last = session || events[events.length - 1]?.session;
  return last ? events.filter((e) => e.session === last) : [];
}

function sessionSummary(events: XrayEvent[]): { session: string; count: number; from: number; to: number }[] {
  const m = new Map<string, { session: string; count: number; from: number; to: number }>();
  for (const e of events) {
    const s = m.get(e.session) ?? { session: e.session, count: 0, from: e.ts, to: e.ts };
    s.count++;
    s.to = e.ts;
    m.set(e.session, s);
  }
  return [...m.values()];
}

function stream(res: http.ServerResponse): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-store",
    "connection": "keep-alive",
  });
  res.write(": connected\n\n");
  const stop = followEvents((e) => {
    try { res.write("data: " + JSON.stringify(e) + "\n\n"); }
    catch { /* client went away; 'close' cleans up */ }
  });
  const ping = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { /* same as above */ }
  }, 15000);
  res.on("close", () => { clearInterval(ping); stop(); });
}

function json(res: http.ServerResponse, body: unknown): void {
  res.writeHead(200, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}
