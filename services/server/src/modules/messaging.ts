import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { MAX_ENVELOPE_BYTES } from "@ollo/shared";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { pushToDevice } from "../realtime/hub.js";
import { randomUuid } from "../security/crypto-utils.js";

const envelopeIn = z.object({
  id: z.string().uuid().optional(),
  recipient_user_id: z.string().uuid(),
  recipient_device_id: z.string().uuid(),
  group_id: z.string().uuid().optional(),
  kind: z.enum(["message", "receipt", "typing", "call", "control"]),
  ciphertext: z.string().min(1),
  padding_bucket: z.number().int().positive(),
  ttl_seconds: z.number().int().nonnegative().optional(),
});

export async function registerMessaging(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/envelopes", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ envelopes: z.array(envelopeIn).min(1).max(256) }).parse(req.body);
    const stored = [];
    for (const env of body.envelopes) {
      const payload = Buffer.from(env.ciphertext, "base64");
      if (payload.length > MAX_ENVELOPE_BYTES) {
        throw new ApiError("payload_too_large", "Envelope too large", 413);
      }
      const blocked = await db.query(
        `SELECT 1 FROM blocks
         WHERE (user_id = $1 AND blocked_user_id = $2)
            OR (user_id = $2 AND blocked_user_id = $1)`,
        [auth.userId, env.recipient_user_id],
      );
      if (blocked.rows[0] && env.kind === "message") {
        throw new ApiError("forbidden", "User is blocked", 403);
      }
      const dest = await db.query<{ id: string; revoked_at: string | null }>(
        "SELECT id, revoked_at FROM devices WHERE id = $1 AND user_id = $2",
        [env.recipient_device_id, env.recipient_user_id],
      );
      if (!dest.rows[0] || dest.rows[0].revoked_at) {
        throw new ApiError("not_found", "Recipient device not found", 404);
      }
      const id = env.id ?? randomUuid();
      const expires = env.ttl_seconds
        ? new Date(Date.now() + env.ttl_seconds * 1000).toISOString()
        : new Date(Date.now() + config.envelopeTtlDays * 86400_000).toISOString();
      await db.query(
        `INSERT INTO envelopes (
           id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
           group_id, kind, payload, padding_bucket, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO NOTHING`,
        [
          id,
          auth.userId,
          auth.deviceId,
          env.recipient_user_id,
          env.recipient_device_id,
          env.group_id ?? null,
          env.kind,
          payload,
          env.padding_bucket,
          expires,
        ],
      );
      const wire = {
        id,
        sender_user_id: auth.userId,
        sender_device_id: auth.deviceId,
        recipient_user_id: env.recipient_user_id,
        recipient_device_id: env.recipient_device_id,
        group_id: env.group_id ?? null,
        kind: env.kind,
        ciphertext: payload.toString("base64"),
        padding_bucket: env.padding_bucket,
        created_at: new Date().toISOString(),
      };
      pushToDevice(env.recipient_device_id, { op: "envelope", envelope: wire });
      stored.push({ id });
    }
    return { accepted: stored };
  });

  app.get("/v1/envelopes", async (req) => {
    const auth = requireAuth(req);
    const q = req.query as { cursor?: string; limit?: string };
    const limit = Math.min(Number(q.limit ?? 100), 200);
    const params: unknown[] = [auth.deviceId];
    let sql = `SELECT id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
                      group_id, kind, payload, padding_bucket, created_at
               FROM envelopes
               WHERE recipient_device_id = $1 AND acked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > now())`;
    if (q.cursor) {
      params.push(q.cursor);
      sql += ` AND id > $2`;
    }
    sql += ` ORDER BY created_at ASC LIMIT ${limit}`;
    const r = await db.query<{
      id: string;
      sender_user_id: string;
      sender_device_id: string;
      recipient_user_id: string;
      recipient_device_id: string;
      group_id: string | null;
      kind: string;
      payload: Buffer;
      padding_bucket: number;
      created_at: string;
    }>(sql, params);
    return {
      envelopes: r.rows.map((e) => ({
        id: e.id,
        sender_user_id: e.sender_user_id,
        sender_device_id: e.sender_device_id,
        recipient_user_id: e.recipient_user_id,
        recipient_device_id: e.recipient_device_id,
        group_id: e.group_id,
        kind: e.kind,
        ciphertext: Buffer.isBuffer(e.payload) ? e.payload.toString("base64") : Buffer.from(e.payload).toString("base64"),
        padding_bucket: e.padding_bucket,
        created_at: e.created_at,
      })),
      next_cursor: r.rows.length === limit ? r.rows[r.rows.length - 1]!.id : null,
    };
  });

  app.post("/v1/envelopes/ack", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ ids: z.array(z.string().uuid()).min(1).max(500) }).parse(req.body);
    await db.query(
      `UPDATE envelopes SET acked_at = now()
       WHERE recipient_device_id = $1 AND id = ANY($2::uuid[])`,
      [auth.deviceId, body.ids],
    );
    return { ok: true };
  });

  app.put("/v1/drafts/:threadId", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ ciphertext: z.string() }).parse(req.body);
    await db.query(
      `INSERT INTO drafts (user_id, device_id, thread_id, ciphertext, updated_at)
       VALUES ($1,$2,$3,$4,now())
       ON CONFLICT (user_id, device_id, thread_id)
       DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()`,
      [
        auth.userId,
        auth.deviceId,
        (req.params as { threadId: string }).threadId,
        Buffer.from(body.ciphertext, "base64"),
      ],
    );
    return { ok: true };
  });

  app.post("/v1/maintenance/expire", async (req) => {
    requireAuth(req);
    await db.query("DELETE FROM envelopes WHERE expires_at IS NOT NULL AND expires_at < now()");
    await db.query("DELETE FROM attachments WHERE expires_at < now() AND completed_at IS NOT NULL");
    return { ok: true };
  });
}
