import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const home = os.homedir();
export const AGENTS = [
    {
        id: "claude", name: "Claude Code", probe: path.join(home, ".claude"),
        schema: "claude",
        settingsFile: () => process.env.CLAUDE_CONFIG_DIR
            ? path.join(process.env.CLAUDE_CONFIG_DIR, "settings.json")
            : path.join(home, ".claude", "settings.json"),
        note: "PreToolUse hook — full support (block / ask / log)",
    },
    {
        id: "zcode", name: "ZCode", probe: path.join(home, ".zcode"),
        schema: "zcode",
        settingsFile: () => path.join(home, ".zcode", "cli", "config.json"),
        note: "PreToolUse hook in ~/.zcode/cli/config.json — needs restart",
    },
    {
        id: "cursor", name: "Cursor", probe: path.join(home, ".cursor"),
        schema: "cursor",
        settingsFile: () => path.join(home, ".cursor", "hooks.json"),
        note: "beforeShellExecution + beforeReadFile hooks (beta)",
    },
    {
        id: "codex", name: "Codex CLI", probe: path.join(home, ".codex"),
        schema: "none",
        settingsFile: () => path.join(home, ".codex", "config.toml"),
        note: "no hook API yet — needs the proxy mode (roadmap)",
    },
    {
        id: "gemini", name: "Gemini CLI", probe: path.join(home, ".gemini"),
        schema: "none",
        settingsFile: () => path.join(home, ".gemini"),
        note: "no hook API yet — needs the proxy mode (roadmap)",
    },
    {
        id: "opencode", name: "OpenCode", probe: path.join(home, ".config", "opencode"),
        schema: "none",
        settingsFile: () => path.join(home, ".config", "opencode"),
        note: "plugin API — adapter on the roadmap",
    },
    {
        id: "windsurf", name: "Windsurf", probe: path.join(home, ".codeium"),
        schema: "none",
        settingsFile: () => path.join(home, ".codeium"),
        note: "no hook API yet — needs the proxy mode (roadmap)",
    },
    {
        id: "aider", name: "Aider", probe: path.join(home, ".aider.conf.yml"),
        schema: "none",
        settingsFile: () => path.join(home, ".aider.conf.yml"),
        note: "no hook API — a terminal tool, not an agent loop",
    },
];
const exists = (p) => {
    try {
        return fs.existsSync(p);
    }
    catch {
        return false;
    }
};
export function listAgents() {
    return AGENTS.map((a) => ({ ...a, installed: exists(a.probe) }));
}
