import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { randomUuid } from "../security/crypto-utils.js";

const MAX_BACKUP_BYTES = 8 * 1024 * 1024;

export async function registerBackups(app: FastifyInstance, db: Db): Promise<void> {
  app.put("/v1/backups", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ blob: z.string().min(16) }).parse(req.body);
    const payload = Buffer.from(body.blob, "base64");
    if (payload.length > MAX_BACKUP_BYTES) {
      throw new ApiError("payload_too_large", "Backup too large", 413);
    }
    const id = randomUuid();
    await db.query("INSERT INTO backups (id, user_id, payload, size) VALUES ($1,$2,$3,$4)", [
      id,
      auth.userId,
      payload,
      payload.length,
    ]);
    await db.query(
      `DELETE FROM backups WHERE user_id = $1 AND id NOT IN (
         SELECT id FROM backups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 3
       )`,
      [auth.userId],
    );
    return { id, size: payload.length };
  });

  app.get("/v1/backups/latest", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{ id: string; payload: Buffer; size: number; created_at: string }>(
      "SELECT id, payload, size, created_at FROM backups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
      [auth.userId],
    );
    const row = r.rows[0];
    if (!row) throw new ApiError("not_found", "No backup", 404);
    return {
      id: row.id,
      blob: Buffer.isBuffer(row.payload) ? row.payload.toString("base64") : Buffer.from(row.payload).toString("base64"),
      size: row.size,
      created_at: row.created_at,
    };
  });
}
