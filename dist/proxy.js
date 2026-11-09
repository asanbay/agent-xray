import http from "node:http";
import net from "node:net";
import { appendEvent } from "./store.js";
import { loadRules, evaluateHost } from "./rules.js";
import { loadConfig, verifySeal } from "./config.js";
/**
 * `agent-xray proxy` — a localhost HTTP(S) proxy that gives domain-level
 * visibility for ANY agent, including the ones without a hook API
 * (Codex CLI, Gemini CLI, Aider…). Point the agent at it:
 *
 *   HTTPS_PROXY=http://127.0.0.1:8080 HTTP_PROXY=http://127.0.0.1:8080 <agent>
 *
 * observe: every host is logged, nothing is blocked.
 * guard:   warn/block-level hosts are refused at CONNECT with 403.
 * HTTPS is tunneled, not decrypted — hostnames only, never contents.
 */
function logConnect(session, host, level, reason, rule, via = "proxy") {
    appendEvent({
        ts: Date.now(), session, tool: via, kind: "network", op: "connect",
        target: host, level, ...(reason ? { reason } : {}), ...(rule ? { rule } : {}),
    });
}
function judge(host, seal) {
    if (!seal.ok)
        return { level: "block", reason: `${seal.detail} — reseal as a human (🫖)` };
    return evaluateHost(host, false, loadRulesCache.rules);
}
// rules are reloaded per request via loadRules() — keep a tiny wrapper so
// both HTTP and CONNECT paths share one evaluation entry point.
const loadRulesCache = {
    get rules() { return loadRules(); },
};
export function startProxy(opts = {}) {
    const wanted = opts.port ?? 8080;
    return new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
            // plain-HTTP proxying: the request URL is absolute (GET http://host/path)
            let host = "unknown";
            try {
                host = new URL(req.url ?? "http://unknown").hostname;
            }
            catch { /* keep unknown */ }
            const seal = verifySeal();
            const v = judge(host, seal);
            logConnect("proxy", host, v.level, v.reason, v.rule);
            const cfg = loadConfig();
            if (cfg.mode === "guard" && (v.level === "block" || v.level === "warn")) {
                res.writeHead(403, { "content-type": "text/plain" });
                res.end(`agent-xray: ${host} is refused in guard mode (${v.reason ?? "flagged"}) — 🫖`);
                return;
            }
            const headers = { ...req.headers };
            delete headers.proxyauthorization;
            delete headers["proxy-connection"];
            const up = http.request(req.url ?? "/", { method: req.method, headers }, (ur) => {
                res.writeHead(ur.statusCode ?? 502, ur.headers);
                ur.pipe(res);
            });
            up.on("error", () => { try {
                res.writeHead(502);
                res.end("agent-xray: upstream error");
            }
            catch { /* gone */ } });
            req.pipe(up);
        });
        server.on("connect", (req, clientSocket, head) => {
            const [host, port] = (req.url ?? "").split(":");
            const seal = verifySeal();
            const v = judge(host ?? "unknown", seal);
            logConnect("proxy", host ?? "unknown", v.level, v.reason, v.rule);
            const cfg = loadConfig();
            if (cfg.mode === "guard" && (v.level === "block" || v.level === "warn")) {
                clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
                clientSocket.end(`agent-xray: ${host} is refused in guard mode (${v.reason ?? "flagged"}) — 🫖\n`);
                return;
            }
            const up = net.connect(Number(port) || 443, host ?? "", () => {
                clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
                if (head && head.length)
                    up.write(head);
                up.pipe(clientSocket);
                clientSocket.pipe(up);
            });
            up.on("error", () => clientSocket.destroy());
            clientSocket.on("error", () => up.destroy());
            clientSocket.on("close", () => up.destroy()); // clean up tunnels when the client walks away
        });
        server.on("clientError", (_err, socket) => {
            try {
                socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
            }
            catch { /* gone */ }
        });
        server.on("error", reject);
        server.listen(wanted, "127.0.0.1", () => {
            const a = server.address();
            const port = typeof a === "object" && a ? a.port : wanted;
            resolve({ url: `http://127.0.0.1:${port}`, port, server });
        });
    });
}
