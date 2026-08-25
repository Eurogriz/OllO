import { redactObject, SENSITIVE_FIELD_RE } from "@ollo/shared";

type Level = "debug" | "info" | "warn" | "error";

function sanitize(meta?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!meta) return undefined;
  return redactObject(meta);
}

function write(level: Level, msg: string, meta?: Record<string, unknown>): void {
  if (SENSITIVE_FIELD_RE.test(msg)) {
    msg = "[redacted-log-message]";
  }
  const line = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...sanitize(meta),
  };
  const s = JSON.stringify(line);
  if (level === "error") console.error(s);
  else console.log(s);
}

export const log = {
  debug: (msg: string, meta?: Record<string, unknown>) => write("debug", msg, meta),
  info: (msg: string, meta?: Record<string, unknown>) => write("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => write("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => write("error", msg, meta),
};
