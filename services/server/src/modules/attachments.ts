import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { getObject, newObjectKey, objectExists, putObject } from "../objects.js";
import { randomToken, randomUuid, sha256Hex } from "../security/crypto-utils.js";

async function grantAllows(db: Db, attachmentId: string, token: string, userId: string): Promise<boolean> {
  const g = await db.query<{ recipient_user_id: string | null; group_id: string | null; expires_at: string }>(
    "SELECT recipient_user_id, group_id, expires_at FROM attachment_grants WHERE token_hash = $1 AND attachment_id = $2",
    [sha256Hex(token), attachmentId],
  );
  const row = g.rows[0];
  if (!row || new Date(row.expires_at).getTime() <= Date.now()) return false;
  if (row.recipient_user_id && row.recipient_user_id === userId) return true;
  if (row.group_id) {
    const mem = await db.query(
      "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
      [row.group_id, userId],
    );
    return Boolean(mem.rows[0]);
  }
  return false;
}

export async function registerAttachments(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/attachments", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        size: z.number().int().positive().max(config.attachmentMaxBytes),
        digest: z.string().optional(),
      })
      .parse(req.body ?? { size: 1 });
    if (body.size > config.attachmentMaxBytes) {
      throw new ApiError("payload_too_large", "File too large", 413);
    }
    const id = randomUuid();
    const key = newObjectKey();
    const expires = new Date(Date.now() + config.attachmentTtlDays * 86400_000);
    await db.query(
      `INSERT INTO attachments (id, uploader_device_id, object_key, size, expires_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [id, auth.deviceId, key, body.size, expires.toISOString()],
    );
    return {
      object_id: id,
      upload_path: `/v1/attachments/${id}/data`,
      expires_at: expires.toISOString(),
    };
  });

  app.put("/v1/attachments/:id/data", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const row = await db.query<{ object_key: string; uploader_device_id: string; size: number }>(
      "SELECT object_key, uploader_device_id, size FROM attachments WHERE id = $1",
      [id],
    );
    const a = row.rows[0];
    if (!a || a.uploader_device_id !== auth.deviceId) {
      throw new ApiError("not_found", "Attachment not found", 404);
    }
    const buf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body as ArrayBuffer);
    if (buf.length > config.attachmentMaxBytes) {
      throw new ApiError("payload_too_large", "File too large", 413);
    }
    await putObject(a.object_key, buf);
    await db.query("UPDATE attachments SET size = $2, completed_at = now() WHERE id = $1", [id, buf.length]);
    return { ok: true, size: buf.length };
  });

  app.post("/v1/attachments/:id/complete", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const body = z.object({ digest: z.string(), size: z.number().int().nonnegative() }).parse(req.body);
    const row = await db.query<{ object_key: string; uploader_device_id: string }>(
      "SELECT object_key, uploader_device_id FROM attachments WHERE id = $1",
      [id],
    );
    const a = row.rows[0];
    if (!a || a.uploader_device_id !== auth.deviceId) {
      throw new ApiError("not_found", "Attachment not found", 404);
    }
    await db.query("UPDATE attachments SET digest = $2, size = $3, completed_at = now() WHERE id = $1", [
      id,
      Buffer.from(body.digest, "hex"),
      body.size,
    ]);
    return { ok: true };
  });

  app.post("/v1/attachments/:id/grants", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const body = z
      .object({
        recipient_user_id: z.string().uuid().optional(),
        group_id: z.string().uuid().optional(),
      })
      .refine((v) => Boolean(v.recipient_user_id || v.group_id), { message: "recipient or group required" })
      .parse(req.body);
    const row = await db.query<{ uploader_device_id: string }>(
      "SELECT uploader_device_id FROM attachments WHERE id = $1",
      [id],
    );
    if (!row.rows[0]) throw new ApiError("not_found", "Attachment not found", 404);
    if (body.group_id) {
      const mem = await db.query(
        "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
        [body.group_id, auth.userId],
      );
      if (!mem.rows[0]) throw new ApiError("forbidden", "Not a group member", 403);
    }
    const token = randomToken(24);
    const exp = new Date(Date.now() + 7 * 86400_000);
    await db.query(
      `INSERT INTO attachment_grants (token_hash, attachment_id, recipient_user_id, group_id, expires_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [sha256Hex(token), id, body.recipient_user_id ?? null, body.group_id ?? null, exp.toISOString()],
    );
    return { grant: token, expires_at: exp.toISOString() };
  });

  app.get("/v1/attachments/:id", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const q = req.query as { grant?: string };
    const row = await db.query<{ object_key: string; uploader_device_id: string; completed_at: string | null }>(
      "SELECT object_key, uploader_device_id, completed_at FROM attachments WHERE id = $1",
      [id],
    );
    const a = row.rows[0];
    if (!a || !a.completed_at) throw new ApiError("not_found", "Attachment not found", 404);
    let allowed = a.uploader_device_id === auth.deviceId;
    if (!allowed && q.grant) {
      allowed = await grantAllows(db, id, q.grant, auth.userId);
    }
    if (!allowed) throw new ApiError("forbidden", "No download grant", 403);
    return { download_path: `/v1/attachments/${id}/data`, grant: q.grant ?? null };
  });

  app.get("/v1/attachments/:id/data", async (req, reply) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const q = req.query as { grant?: string };
    const row = await db.query<{ object_key: string; uploader_device_id: string }>(
      "SELECT object_key, uploader_device_id FROM attachments WHERE id = $1",
      [id],
    );
    const a = row.rows[0];
    if (!a || !(await objectExists(a.object_key))) throw new ApiError("not_found", "Attachment not found", 404);
    let allowed = a.uploader_device_id === auth.deviceId;
    if (!allowed && q.grant) {
      allowed = await grantAllows(db, id, q.grant, auth.userId);
    }
    if (!allowed) throw new ApiError("forbidden", "No download grant", 403);
    const buf = await getObject(a.object_key);
    return reply
      .header("content-type", "application/octet-stream")
      .header("cache-control", "no-store")
      .send(buf);
  });
}
