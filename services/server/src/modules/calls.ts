import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { randomUuid } from "../security/crypto-utils.js";

export async function registerCalls(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/calls", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        media: z.enum(["audio", "video"]),
        participant_user_ids: z.array(z.string().uuid()).min(1).max(16),
      })
      .parse(req.body);
    const id = randomUuid();
    await db.query("INSERT INTO calls (id, created_by, media) VALUES ($1,$2,$3)", [
      id,
      auth.userId,
      body.media,
    ]);
    await db.query(
      "INSERT INTO call_participants (call_id, user_id, device_id) VALUES ($1,$2,$3)",
      [id, auth.userId, auth.deviceId],
    );
    for (const uid of body.participant_user_ids) {
      await db.query(
        "INSERT INTO call_participants (call_id, user_id, device_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        [id, uid, auth.deviceId],
      );
    }
    return {
      call_id: id,
      ice_servers: [
        ...config.stunUrls.map((urls) => ({ urls })),
        ...config.turnUrls.map((urls) => ({
          urls,
          username: config.turnUsername || undefined,
          credential: config.turnPassword || undefined,
        })),
      ],
    };
  });

  app.post("/v1/calls/:id/join", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const c = await db.query<{ id: string; ended_at: string | null }>(
      "SELECT id, ended_at FROM calls WHERE id = $1",
      [id],
    );
    if (!c.rows[0] || c.rows[0].ended_at) throw new ApiError("not_found", "Call not found", 404);
    await db.query(
      `INSERT INTO call_participants (call_id, user_id, device_id) VALUES ($1,$2,$3)
       ON CONFLICT DO NOTHING`,
      [id, auth.userId, auth.deviceId],
    );
    return { ok: true };
  });

  app.post("/v1/calls/:id/end", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    await db.query("UPDATE calls SET ended_at = now() WHERE id = $1 AND created_by = $2", [id, auth.userId]);
    return { ok: true };
  });

  app.get("/v1/calls/history", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{
      id: string;
      media: string;
      created_at: string;
      ended_at: string | null;
      created_by: string;
    }>(
      `SELECT c.id, c.media, c.created_at, c.ended_at, c.created_by
       FROM calls c JOIN call_participants p ON p.call_id = c.id
       WHERE p.user_id = $1
       ORDER BY c.created_at DESC LIMIT 50`,
      [auth.userId],
    );
    return { calls: r.rows };
  });
}
