/**
 * Privacy-preserving wakeup plane.
 * Payloads never contain plaintext, sender names, or previews.
 */
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { requireAuth } from "../http.js";
import { isOnline } from "../realtime/hub.js";

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
    return { ok: true, payload: { v: 1, t: "msg" } };
  });
}

export async function maybeWake(db: Db, recipientUserId: string, recipientDeviceId: string): Promise<void> {
  if (isOnline(recipientUserId)) return;
  const tok = await db.query<{ push_token_enc: Buffer | null }>(
    "SELECT push_token_enc FROM devices WHERE id = $1 AND revoked_at IS NULL",
    [recipientDeviceId],
  );
  if (!tok.rows[0]?.push_token_enc) return;
  // Production: FCM / APNs data message {v:1,t:"msg"} only. No body.
}
