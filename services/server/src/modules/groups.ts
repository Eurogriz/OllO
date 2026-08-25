import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { pushToDevice } from "../realtime/hub.js";
import { randomToken, randomUuid, sha256Hex } from "../security/crypto-utils.js";

async function requireMember(db: Db, groupId: string, userId: string) {
  const r = await db.query<{ role: string }>(
    "SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
    [groupId, userId],
  );
  if (!r.rows[0]) throw new ApiError("forbidden", "Not a group member", 403);
  return r.rows[0];
}

export async function registerGroups(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/groups", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ member_ids: z.array(z.string().uuid()).max(256) }).parse(req.body ?? {});
    const id = randomUuid();
    await db.query("INSERT INTO groups (id, creator_id, epoch) VALUES ($1,$2,1)", [id, auth.userId]);
    const members = new Set([auth.userId, ...body.member_ids]);
    for (const uid of members) {
      await db.query(
        `INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,$3)`,
        [id, uid, uid === auth.userId ? "admin" : "member"],
      );
    }
    return { group: { id, epoch: 1, role: "admin" } };
  });

  app.get("/v1/groups", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{ id: string; epoch: number; role: string; creator_id: string }>(
      `SELECT g.id, g.epoch, m.role, g.creator_id
       FROM group_members m JOIN groups g ON g.id = m.group_id
       WHERE m.user_id = $1 AND m.removed_at IS NULL AND g.deleted_at IS NULL`,
      [auth.userId],
    );
    return { groups: r.rows };
  });

  app.get("/v1/groups/:id", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    await requireMember(db, id, auth.userId);
    const g = await db.query<{ id: string; epoch: number; creator_id: string }>(
      "SELECT id, epoch, creator_id FROM groups WHERE id = $1",
      [id],
    );
    const members = await db.query<{ user_id: string; role: string }>(
      "SELECT user_id, role FROM group_members WHERE group_id = $1 AND removed_at IS NULL",
      [id],
    );
    return { group: { ...g.rows[0], members: members.rows } };
  });

  app.post("/v1/groups/:id/members", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const me = await requireMember(db, id, auth.userId);
    if (me.role !== "admin" && me.role !== "moderator") {
      throw new ApiError("forbidden", "Insufficient role", 403);
    }
    const body = z.object({ user_id: z.string().uuid(), role: z.enum(["member", "moderator"]).optional() }).parse(
      req.body,
    );
    await db.query(
      `INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,$3)
       ON CONFLICT (group_id, user_id) DO UPDATE SET removed_at = NULL, role = EXCLUDED.role`,
      [id, body.user_id, body.role ?? "member"],
    );
    const epoch = await bumpEpoch(db, id);
    return { ok: true, epoch };
  });

  app.delete("/v1/groups/:id/members/:userId", async (req) => {
    const auth = requireAuth(req);
    const { id, userId } = req.params as { id: string; userId: string };
    const me = await requireMember(db, id, auth.userId);
    if (userId !== auth.userId && me.role !== "admin") {
      throw new ApiError("forbidden", "Insufficient role", 403);
    }
    await db.query(
      "UPDATE group_members SET removed_at = now() WHERE group_id = $1 AND user_id = $2",
      [id, userId],
    );
    const epoch = await bumpEpoch(db, id);
    return { ok: true, epoch };
  });

  app.post("/v1/groups/:id/epoch", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    await requireMember(db, id, auth.userId);
    const epoch = await bumpEpoch(db, id);
    return { epoch };
  });

  app.post("/v1/groups/:id/invites", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const me = await requireMember(db, id, auth.userId);
    if (me.role !== "admin") throw new ApiError("forbidden", "Insufficient role", 403);
    const token = randomToken(18);
    const exp = new Date(Date.now() + 7 * 86400_000);
    await db.query(
      `INSERT INTO group_invites (token_hash, group_id, created_by, expires_at) VALUES ($1,$2,$3,$4)`,
      [sha256Hex(token), id, auth.userId, exp.toISOString()],
    );
    return { token, expires_at: exp.toISOString() };
  });

  app.post("/v1/groups/:id/fanout", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    await requireMember(db, id, auth.userId);
    const body = z
      .object({
        kind: z.enum(["message", "receipt", "typing", "call", "control"]),
        ciphertext: z.string().min(1),
        padding_bucket: z.number().int().positive(),
        ttl_seconds: z.number().int().nonnegative().optional(),
      })
      .parse(req.body);
    const payload = Buffer.from(body.ciphertext, "base64");
    if (payload.length > 256 * 1024) {
      throw new ApiError("payload_too_large", "Envelope too large", 413);
    }
    const members = await db.query<{ user_id: string }>(
      "SELECT user_id FROM group_members WHERE group_id = $1 AND removed_at IS NULL",
      [id],
    );
    const expires = body.ttl_seconds
      ? new Date(Date.now() + body.ttl_seconds * 1000).toISOString()
      : new Date(Date.now() + 30 * 86400_000).toISOString();
    let n = 0;
    for (const m of members.rows) {
      const devices = await db.query<{ id: string }>(
        "SELECT id FROM devices WHERE user_id = $1 AND revoked_at IS NULL",
        [m.user_id],
      );
      for (const d of devices.rows) {
        if (d.id === auth.deviceId) continue;
        const eid = randomUuid();
        await db.query(
          `INSERT INTO envelopes (
             id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
             group_id, kind, payload, padding_bucket, expires_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            eid,
            auth.userId,
            auth.deviceId,
            m.user_id,
            d.id,
            id,
            body.kind,
            payload,
            body.padding_bucket,
            expires,
          ],
        );
        pushToDevice(d.id, {
          op: "envelope",
          envelope: {
            id: eid,
            sender_user_id: auth.userId,
            sender_device_id: auth.deviceId,
            recipient_user_id: m.user_id,
            recipient_device_id: d.id,
            group_id: id,
            kind: body.kind,
            ciphertext: body.ciphertext,
            padding_bucket: body.padding_bucket,
            created_at: new Date().toISOString(),
          },
        });
        n += 1;
      }
    }
    return { accepted: n };
  });

  app.post("/v1/groups/join/:token", async (req) => {
    const auth = requireAuth(req);
    const token = (req.params as { token: string }).token;
    const r = await db.query<{ group_id: string; expires_at: string; used_at: string | null }>(
      "SELECT group_id, expires_at, used_at FROM group_invites WHERE token_hash = $1",
      [sha256Hex(token)],
    );
    const inv = r.rows[0];
    if (!inv || inv.used_at || new Date(inv.expires_at).getTime() < Date.now()) {
      throw new ApiError("not_found", "Invite not found", 404);
    }
    await db.query(
      `INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,'member')
       ON CONFLICT (group_id, user_id) DO UPDATE SET removed_at = NULL`,
      [inv.group_id, auth.userId],
    );
    const epoch = await bumpEpoch(db, inv.group_id);
    return { group_id: inv.group_id, epoch };
  });
}

async function bumpEpoch(db: Db, groupId: string): Promise<number> {
  const r = await db.query<{ epoch: number }>(
    "UPDATE groups SET epoch = epoch + 1 WHERE id = $1 RETURNING epoch",
    [groupId],
  );
  return r.rows[0]?.epoch ?? 0;
}
