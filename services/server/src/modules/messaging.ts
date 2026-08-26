import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { MAX_ENVELOPE_BYTES } from "@ollo/shared";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { maybeWake } from "./notifications.js";
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

export interface MailboxEnvelope {
  id: string;
  sender_user_id: string;
  sender_device_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
  group_id: string | null;
  kind: string;
  ciphertext: string;
  padding_bucket: number;
  created_at: string;
}

function wireEnvelope(e: {
  id: string;
  sender_user_id: string;
  sender_device_id: string;
  recipient_user_id: string;
  recipient_device_id: string;
  group_id: string | null;
  kind: string;
  payload: Buffer | Uint8Array;
  padding_bucket: number;
  created_at: string;
}): MailboxEnvelope {
  const payload = Buffer.isBuffer(e.payload) ? e.payload : Buffer.from(e.payload);
  return {
    id: e.id,
    sender_user_id: e.sender_user_id,
    sender_device_id: e.sender_device_id,
    recipient_user_id: e.recipient_user_id,
    recipient_device_id: e.recipient_device_id,
    group_id: e.group_id,
    kind: e.kind,
    ciphertext: payload.toString("base64"),
    padding_bucket: e.padding_bucket,
    created_at: e.created_at,
  };
}

export async function listMailbox(
  db: Db,
  deviceId: string,
  cursor?: string,
  limit = 100,
): Promise<{ envelopes: MailboxEnvelope[]; next_cursor: string | null }> {
  const cap = Number.isFinite(limit) ? Math.min(Math.max(Math.trunc(limit), 1), 200) : 100;
  if (cursor && !z.string().uuid().safeParse(cursor).success) {
    throw new ApiError("validation", "Invalid request", 400);
  }
  const params: unknown[] = [deviceId];
  let sql = `SELECT id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
                    group_id, kind, payload, padding_bucket, created_at
             FROM envelopes
             WHERE recipient_device_id = $1 AND acked_at IS NULL
               AND (expires_at IS NULL OR expires_at > now())`;
  if (cursor) {
    params.push(cursor);
    sql += ` AND (created_at, id) > (
      SELECT created_at, id FROM envelopes
      WHERE id = $${params.length} AND recipient_device_id = $1
    )`;
  }
  params.push(cap);
  sql += ` ORDER BY created_at ASC, id ASC LIMIT $${params.length}`;
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
    envelopes: r.rows.map(wireEnvelope),
    next_cursor: r.rows.length === cap ? r.rows[r.rows.length - 1]!.id : null,
  };
}

export async function ackEnvelopes(db: Db, deviceId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  await db.query(
    `DELETE FROM envelopes
     WHERE recipient_device_id = $1 AND id = ANY($2::uuid[])`,
    [deviceId, ids],
  );
}

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
      const inserted = await db.query<{ id: string }>(
        `INSERT INTO envelopes (
           id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
           group_id, kind, payload, padding_bucket, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO NOTHING
         RETURNING id`,
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
      if (!inserted.rows[0]) {
        const existing = await db.query<{
          sender_device_id: string;
          recipient_device_id: string;
        }>("SELECT sender_device_id, recipient_device_id FROM envelopes WHERE id = $1", [id]);
        const row = existing.rows[0];
        if (
          row &&
          row.sender_device_id === auth.deviceId &&
          row.recipient_device_id === env.recipient_device_id
        ) {
          stored.push({ id });
          continue;
        }
        throw new ApiError("conflict", "Envelope id already used", 409);
      }
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
      if (env.kind === "message" || env.kind === "call") {
        await maybeWake(db, env.recipient_user_id, env.recipient_device_id, env.kind === "call" ? "call" : "msg");
      }
      stored.push({ id });
    }
    return { accepted: stored };
  });

  app.get("/v1/envelopes", async (req) => {
    const auth = requireAuth(req);
    const q = z
      .object({
        cursor: z.string().uuid().optional(),
        limit: z.string().optional(),
      })
      .parse(req.query ?? {});
    const parsed = Number.parseInt(q.limit ?? "100", 10);
    const limit = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 1), 200) : 100;
    return listMailbox(db, auth.deviceId, q.cursor, limit);
  });

  app.post("/v1/envelopes/ack", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ ids: z.array(z.string().uuid()).min(1).max(500) }).parse(req.body);
    await ackEnvelopes(db, auth.deviceId, body.ids);
    return { ok: true };
  });

  app.put("/v1/drafts/:threadId", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ ciphertext: z.string().max(350_000) }).parse(req.body);
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
}
