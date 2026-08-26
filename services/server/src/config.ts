import { assertNeverDevReveal } from "@ollo/shared";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnv(): void {
  const p = resolve(process.cwd(), ".env");
  const root = resolve(process.cwd(), "../../.env");
  const file = existsSync(p) ? p : existsSync(root) ? root : null;
  if (!file) return;
  for (const line of readFileSync(file, "utf8").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i < 0) continue;
    const k = t.slice(0, i).trim();
    const v = t.slice(i + 1).trim();
    if (!(k in process.env)) process.env[k] = v;
  }
}

loadDotEnv();

function req(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined) throw new Error(`missing env ${name}`);
  return v;
}

function bool(name: string, fallback: boolean): boolean {
  const v = process.env[name];
  if (v === undefined) return fallback;
  return v === "1" || v === "true" || v === "yes";
}

const nodeEnv = req("NODE_ENV", "development");
const olloEnv = req("OLLO_ENV", nodeEnv === "production" ? "production" : "development");

export const config = {
  nodeEnv,
  olloEnv,
  isProd: olloEnv === "production",
  host: req("HOST", "0.0.0.0"),
  port: Number(req("PORT", "8080")),
  publicUrl: req("PUBLIC_URL", "http://localhost:8080"),
  logLevel: req("LOG_LEVEL", "info"),
  databaseDriver: req("DATABASE_DRIVER", "pglite"),
  databaseUrl: req("DATABASE_URL", "postgres://ollo:ollo@127.0.0.1:5432/ollo"),
  pgliteDir: req("PGLITE_DATA_DIR", "./data/pglite"),
  redisUrl: process.env.REDIS_URL ?? "",
  redisRequired: bool("REDIS_REQUIRED", false),
  localObjectDir: req("LOCAL_OBJECT_DIR", "./data/objects"),
  s3Endpoint: process.env.S3_ENDPOINT ?? "",
  s3Region: req("S3_REGION", "us-east-1"),
  s3Bucket: process.env.S3_BUCKET ?? "",
  s3AccessKey: process.env.S3_ACCESS_KEY_ID ?? "",
  s3SecretKey: process.env.S3_SECRET_ACCESS_KEY ?? "",
  smsProvider: req("SMS_PROVIDER", "none"),
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID ?? "",
  twilioAuthToken: process.env.TWILIO_AUTH_TOKEN ?? "",
  twilioFromNumber: process.env.TWILIO_FROM_NUMBER ?? "",
  smsHttpUrl: process.env.SMS_HTTP_URL ?? "",
  smsHttpToken: process.env.SMS_HTTP_TOKEN ?? "",
  phonePepper: req("PHONE_HMAC_PEPPER", "change-me-dev-only-phone-pepper"),
  sessionKey: req("SESSION_SIGNING_KEY", "change-me-dev-only-session-key"),
  otpPepper: req("OTP_PEPPER", "change-me-dev-only-otp-pepper"),
  registrationLockPepper: req("REGISTRATION_LOCK_PEPPER", "change-me-dev-only-reglock-pepper"),
  otpLength: Number(req("OTP_LENGTH", "6")),
  otpTtlSeconds: Number(req("OTP_TTL_SECONDS", "300")),
  otpMaxAttempts: Number(req("OTP_MAX_ATTEMPTS", "5")),
  otpDevReveal: bool("OTP_DEV_REVEAL", olloEnv !== "production"),
  rateLimitWindowMs: Number(req("RATE_LIMIT_WINDOW_MS", "60000")),
  rateLimitMax: Number(req("RATE_LIMIT_MAX", "120")),
  attachmentMaxBytes: Number(req("ATTACHMENT_MAX_BYTES", String(100 * 1024 * 1024))),
  attachmentTtlDays: Number(req("ATTACHMENT_TTL_DAYS", "90")),
  envelopeTtlDays: Number(req("OFFLINE_ENVELOPE_TTL_DAYS", "30")),
  stunUrls: req("STUN_URLS", "stun:stun.l.google.com:19302").split(",").filter(Boolean),
  turnUrls: (process.env.TURN_URLS ?? "").split(",").filter(Boolean),
  turnUsername: process.env.TURN_USERNAME ?? "",
  turnPassword: process.env.TURN_PASSWORD ?? "",
  turnSecret: process.env.TURN_SECRET ?? "",
  corsOrigins: (process.env.CORS_ORIGINS ?? "http://localhost:5173,http://127.0.0.1:5173")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
  metricsEnabled: bool("METRICS_ENABLED", true),
};

if (config.isProd) {
  assertNeverDevReveal("production", config.otpDevReveal);
  for (const [k, v] of Object.entries({
    PHONE_HMAC_PEPPER: config.phonePepper,
    SESSION_SIGNING_KEY: config.sessionKey,
    OTP_PEPPER: config.otpPepper,
  })) {
    if (v.startsWith("change-me")) {
      throw new Error(`${k} must be set to a real secret in production`);
    }
  }
}
