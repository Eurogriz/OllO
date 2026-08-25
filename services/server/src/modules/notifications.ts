/**
 * Privacy-preserving wakeup plane.
 * Payloads never contain plaintext, sender names, or previews.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { requireAuth } from "../http.js";
import { isDeviceOnline } from "../realtime/hub.js";

export type SealedWakeKind = "msg" | "call";

export interface SealedWake {
  v: 1;
  t: SealedWakeKind;
}

export interface WakeRecord {
  deviceId: string;
  payload: SealedWake;
  at: string;
}

const recent: WakeRecord[] = [];

export function recentWakes(): WakeRecord[] {
  return [...recent];
}

export function resetWakes(): void {
  recent.length = 0;
}

function wrapKey(): Buffer {
  return createHash("sha256").update(config.sessionKey).update(":push-wrap").digest();
}

export function wrapPushToken(token: string): Buffer {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", wrapKey(), iv);
  const ct = Buffer.concat([c.update(token, "utf8"), c.final()]);
  return Buffer.concat([Buffer.from([1]), iv, c.getAuthTag(), ct]);
}

export function unwrapPushToken(buf: Buffer): string | null {
  if (!buf.length) return null;
  if (buf[0] !== 1 || buf.length < 1 + 12 + 16) {
    return buf.toString("utf8");
  }
  try {
    const iv = buf.subarray(1, 13);
    const tag = buf.subarray(13, 29);
    const ct = buf.subarray(29);
    const d = createDecipheriv("aes-256-gcm", wrapKey(), iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}

export function sealedPayload(kind: SealedWakeKind): SealedWake {
  return { v: 1, t: kind };
}

export function shouldWake(kind: string): boolean {
  return kind === "message" || kind === "call" || kind === "msg";
}

export async function maybeWake(
  db: Db,
  recipientUserId: string,
  recipientDeviceId: string,
  kind: SealedWakeKind = "msg",
): Promise<void> {
  if (!shouldWake(kind)) return;
  if (isDeviceOnline(recipientDeviceId)) return;
  const tok = await db.query<{ push_token_enc: Buffer | null }>(
    "SELECT push_token_enc FROM devices WHERE id = $1 AND revoked_at IS NULL",
    [recipientDeviceId],
  );
  if (!tok.rows[0]?.push_token_enc) return;
  const token = unwrapPushToken(tok.rows[0].push_token_enc);
  if (!token) return;
  const payload = sealedPayload(kind);
  recent.push({ deviceId: recipientDeviceId, payload, at: new Date().toISOString() });
  if (recent.length > 200) recent.splice(0, recent.length - 200);
  void token;
  // Production: FCM / APNs data-only message with `payload` and nothing else.
}

export async function registerNotifications(app: FastifyInstance, db: Db): Promise<void> {
  app.get("/v1/notifications/pending", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM envelopes
       WHERE recipient_device_id = $1 AND acked_at IS NULL
         AND (expires_at IS NULL OR expires_at > now())`,
      [auth.deviceId],
    );
    return { pending: Number(r.rows[0]?.n ?? 0), sealed: true };
  });

  app.post("/v1/notifications/test-wake", async (req) => {
    requireAuth(req);
    z.object({}).parse(req.body ?? {});
    return { ok: true, payload: sealedPayload("msg") };
  });
}
