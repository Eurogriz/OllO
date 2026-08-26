import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { randomUuid } from "../security/crypto-utils.js";
import { iceServersFor } from "../security/turn.js";

async function requireCallParticipant(db: Db, callId: string, userId: string) {
  const r = await db.query<{ user_id: string }>(
    "SELECT user_id FROM call_participants WHERE call_id = $1 AND user_id = $2",
    [callId, userId],
  );
  return Boolean(r.rows[0]);
}

export async function registerCalls(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/calls", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        media: z.enum(["audio", "video"]),
        participant_user_ids: z.array(z.string().uuid()).max(16).optional(),
        group_id: z.string().uuid().optional(),
      })
      .parse(req.body);
    if (body.group_id) {
      const mem = await db.query(
        "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
        [body.group_id, auth.userId],
      );
      if (!mem.rows[0]) throw new ApiError("forbidden", "Not a group member", 403);
    }
    const invited = new Set(body.participant_user_ids ?? []);
    invited.delete(auth.userId);
    for (const uid of invited) {
      const blocked = await db.query(
        `SELECT 1 FROM blocks
         WHERE (user_id = $1 AND blocked_user_id = $2)
            OR (user_id = $2 AND blocked_user_id = $1)`,
        [auth.userId, uid],
      );
      if (blocked.rows[0]) throw new ApiError("forbidden", "User is blocked", 403);
    }
    const id = randomUuid();
    await db.query("INSERT INTO calls (id, created_by, media, group_id) VALUES ($1,$2,$3,$4)", [
      id,
      auth.userId,
      body.media,
      body.group_id ?? null,
    ]);
    await db.query("INSERT INTO call_participants (call_id, user_id, device_id) VALUES ($1,$2,$3)", [
      id,
      auth.userId,
      auth.deviceId,
    ]);
    const invitees = new Set(invited);
    invitees.add(auth.userId);
    for (const uid of invitees) {
      await db.query("INSERT INTO call_invitees (call_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING", [
        id,
        uid,
      ]);
    }
    return {
      call_id: id,
      ice_servers: iceServersFor(auth.userId),
    };
  });

  app.post("/v1/calls/:id/join", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const c = await db.query<{ id: string; ended_at: string | null; created_by: string; group_id: string | null }>(
      "SELECT id, ended_at, created_by, group_id FROM calls WHERE id = $1",
      [id],
    );
    const call = c.rows[0];
    if (!call || call.ended_at) throw new ApiError("not_found", "Call not found", 404);
    if (call.group_id) {
      const mem = await db.query(
        "SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
        [call.group_id, auth.userId],
      );
      if (!mem.rows[0]) throw new ApiError("forbidden", "Not a group member", 403);
    } else {
      const invited = await db.query(
        "SELECT 1 FROM call_invitees WHERE call_id = $1 AND user_id = $2",
        [id, auth.userId],
      );
      if (!invited.rows[0]) throw new ApiError("forbidden", "Not invited to this call", 403);
    }
    await db.query(
      `INSERT INTO call_participants (call_id, user_id, device_id) VALUES ($1,$2,$3)
       ON CONFLICT DO NOTHING`,
      [id, auth.userId, auth.deviceId],
    );
    return { ok: true, ice_servers: iceServersFor(auth.userId) };
  });

  app.post("/v1/calls/:id/end", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const allowed = await requireCallParticipant(db, id, auth.userId);
    if (!allowed) throw new ApiError("forbidden", "Not in this call", 403);
    await db.query("UPDATE calls SET ended_at = now() WHERE id = $1 AND ended_at IS NULL", [id]);
    return { ok: true };
  });

  app.get("/v1/calls/:id", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const c = await db.query<{
      id: string;
      media: string;
      created_by: string;
      created_at: string;
      ended_at: string | null;
      group_id: string | null;
    }>("SELECT id, media, created_by, created_at, ended_at, group_id FROM calls WHERE id = $1", [id]);
    const call = c.rows[0];
    if (!call) throw new ApiError("not_found", "Call not found", 404);
    const inCall = await requireCallParticipant(db, id, auth.userId);
    if (!inCall && call.created_by !== auth.userId) {
      throw new ApiError("forbidden", "Not in this call", 403);
    }
    return { call, ice_servers: iceServersFor(auth.userId) };
  });

  app.get("/v1/me/calls", async (req) => {
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
