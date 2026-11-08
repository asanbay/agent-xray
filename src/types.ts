export type Level = "allow" | "warn" | "block";
export type Kind = "file" | "command" | "network";

export interface Verdict {
  level: Level;
  reason?: string;
  rule?: string;
}

export interface XrayEvent {
  ts: number;
  session: string;
  tool: string;
  kind: Kind;
  op: "read" | "write" | "exec" | "connect";
  /** path, (redacted) command or hostname. Never file contents. */
  target: string;
  level: Level;
  reason?: string;
  rule?: string;
}

export interface CommandRule {
  pattern: string;
  reason: string;
}

export interface Rules {
  file: { allow: string[]; block: string[]; warn: string[] };
  fileWrite: { block: string[]; warn: string[] };
  command: { block: CommandRule[]; warn: CommandRule[] };
  network: { allow: string[]; warn: string[] };
}

export const rank = (l: Level): number => (l === "block" ? 2 : l === "warn" ? 1 : 0);
