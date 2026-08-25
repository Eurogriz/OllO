import { E164_RE, USERNAME_RE, normalizeUsername } from "@ollo/protocol";

export { E164_RE, USERNAME_RE, normalizeUsername };

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const OTP_TTL_SECONDS = 5 * 60;
export const OTP_MAX_ATTEMPTS = 5;
export const MAX_ENVELOPE_BYTES = 256 * 1024;
export const MAX_USERNAME_CHANGES_PER_DAY = 3;
export const PREKEY_MIN_DEPTH = 20;
export const PREKEY_BATCH = 100;

export const SENSITIVE_FIELD_RE =
  /(otp|password|passwd|pin|secret|token|authorization|refresh|private[_-]?key|ciphertext|seed|cookie)/i;

export function redactValue(key: string, value: unknown): unknown {
  if (SENSITIVE_FIELD_RE.test(key)) return "[redacted]";
  return value;
}

export function redactObject(input: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    if (SENSITIVE_FIELD_RE.test(k)) {
      out[k] = "[redacted]";
    } else if (v && typeof v === "object" && !Array.isArray(v) && !(v instanceof Uint8Array)) {
      out[k] = redactObject(v as Record<string, unknown>);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export function assertNeverDevReveal(env: string, flag: boolean): void {
  if (env === "production" && flag) {
    throw new Error("OTP_DEV_REVEAL cannot be enabled in production");
  }
}
