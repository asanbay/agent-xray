/**
 * Scrub anything that looks like a secret before it reaches the log.
 * agent-xray must never become the leak it is trying to detect.
 */
export function redact(s: string): string {
  return s
    .replace(/\b(bearer\s+)[A-Za-z0-9._~+\/=-]{6,}/gi, "$1***")
    .replace(
      /((?:api[_-]?key|access[_-]?key|token|secret|passw(?:or)?d|authorization)["'\s:=]+)([^\s"']{6,})/gi,
      "$1***"
    )
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA***")
    .replace(/\bsk-[A-Za-z0-9_-]{20,}/g, "sk-***")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{30,}/g, "gh*_***")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, "xox*-***");
}
