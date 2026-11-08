import { bold, clock, dim, formatEvent, green, red, yellow } from "./render.js";
export function buildReport(events) {
    const flagged = new Map();
    for (const e of events) {
        if (e.level === "allow")
            continue;
        const k = `${e.kind}|${e.op}|${e.target}|${e.level}`;
        if (!flagged.has(k))
            flagged.set(k, e);
    }
    const all = [...flagged.values()];
    const blocked = all.filter((e) => e.level === "block");
    const warned = all.filter((e) => e.level === "warn");
    const score = Math.max(0, 100 - 20 * blocked.length - 5 * warned.length);
    const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
    return {
        session: events[0]?.session ?? "-",
        from: events[0]?.ts ?? 0,
        to: events[events.length - 1]?.ts ?? 0,
        toolCalls: events.filter((e) => e.kind !== "network" || e.tool === "WebFetch").length,
        filesRead: events.filter((e) => e.kind === "file" && e.op === "read").length,
        filesWritten: events.filter((e) => e.kind === "file" && e.op === "write").length,
        commands: events.filter((e) => e.kind === "command").length,
        hosts: [...new Set(events.filter((e) => e.kind === "network").map((e) => e.target))],
        warned, blocked, score, grade,
    };
}
export function printReport(r, all) {
    const g = r.grade === "A" || r.grade === "B" ? green : r.grade === "C" ? yellow : red;
    console.log(bold(`agent-xray report`) + dim(all ? " — all sessions" : ` — session ${r.session.slice(0, 8)}`));
    if (r.toolCalls === 0) {
        console.log(dim("No events yet. Run `agent-xray install`, then use your agent."));
        return;
    }
    console.log(dim(`${clock(r.from)} → ${clock(r.to)}`));
    console.log();
    console.log(`  Tool calls observed : ${r.toolCalls}`);
    console.log(`  Files read / written: ${r.filesRead} / ${r.filesWritten}`);
    console.log(`  Commands            : ${r.commands}`);
    console.log(`  Network hosts       : ${r.hosts.length}${r.hosts.length ? dim(" (" + r.hosts.slice(0, 6).join(", ") + (r.hosts.length > 6 ? ", …" : "") + ")") : ""}`);
    console.log(`  ${yellow("⚠ Warned")}: ${r.warned.length}    ${red("✖ Blocked")}: ${r.blocked.length}`);
    const flagged = [...r.blocked, ...r.warned].sort((a, b) => a.ts - b.ts);
    if (flagged.length) {
        console.log();
        console.log(bold("  Flagged"));
        for (const e of flagged.slice(0, 15))
            console.log("  " + formatEvent(e));
        if (flagged.length > 15)
            console.log(dim(`  … and ${flagged.length - 15} more`));
    }
    console.log();
    console.log(`  Risk grade: ${g(bold(r.grade))} ${dim(`(${r.score}/100)`)}`);
}
