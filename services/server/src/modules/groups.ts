import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { verifyMembership } from "@ollo/crypto";
import { planFanoutRecipients, sameMembership } from "@ollo/shared";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { pushToDevice } from "../realtime/hub.js";
import { randomToken, randomUuid, sha256Hex } from "../security/crypto-utils.js";
import { maybeWake } from "./notifications.js";

const membershipBody = z.object({
  epoch: z.number().int().positive(),
  members: z
    .array(
      z.object({
        user_id: z.string().uuid(),
        role: z.enum(["admin", "moderator", "member"]),
      }),
    )
    .min(1)
    .max(256),
  signer_user_id: z.string().uuid(),
  signer_device_id: z.string().uuid(),
  signature: z.string().min(1),
});

type MembershipBody = z.infer<typeof membershipBody>;

async function requireMember(db: Db, groupId: string, userId: string) {
  const r = await db.query<{ role: string }>(
    "SELECT role FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
    [groupId, userId],
  );
  if (!r.rows[0]) throw new ApiError("forbidden", "Not a group member", 403);
  return r.rows[0];
}

async function liveMembers(db: Db, groupId: string) {
  const r = await db.query<{ user_id: string; role: string }>(
    "SELECT user_id, role FROM group_members WHERE group_id = $1 AND removed_at IS NULL",
    [groupId],
  );
  return r.rows.map((m) => ({ userId: m.user_id, role: m.role }));
}

/** Previous signed roster only. SQL role is not authority to sign. */
async function loadStoredMembers(db: Db, groupId: string): Promise<{ userId: string; role: string }[] | null> {
  const r = await db.query<{ membership_json: string | null }>(
    "SELECT membership_json FROM groups WHERE id = $1",
    [groupId],
  );
  const raw = r.rows[0]?.membership_json;
  if (!raw) return null;
  try {
    const members = JSON.parse(raw) as Array<{ user_id: string; role: string }>;
    if (!Array.isArray(members) || members.length === 0) return null;
    return members.map((m) => ({ userId: m.user_id, role: m.role }));
  } catch {
    return null;
  }
}

async function loadSignerEd25519(db: Db, userId: string, deviceId: string): Promise<Uint8Array> {
  const r = await db.query<{ identity_ed25519: Uint8Array }>(
    "SELECT identity_ed25519 FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
    [deviceId, userId],
  );
  if (!r.rows[0]) throw new ApiError("forbidden", "Unknown signer device", 403);
  return new Uint8Array(r.rows[0].identity_ed25519);
}

function rowsFromBody(body: MembershipBody) {
  return body.members.map((m) => ({ userId: m.user_id, role: m.role }));
}

async function requireSignedMembership(
  db: Db,
  auth: { userId: string; deviceId: string },
  groupId: string,
  raw: unknown,
  expected: { userId: string; role: string }[],
  epoch: number,
): Promise<MembershipBody> {
  const parsed = membershipBody.safeParse(raw);
  if (!parsed.success) throw new ApiError("validation", "Signed membership required", 400);
  const body = parsed.data;
  if (body.epoch !== epoch) throw new ApiError("validation", "Membership epoch mismatch", 400);
  if (body.signer_user_id !== auth.userId) throw new ApiError("forbidden", "Signer must be the caller", 403);
  if (body.signer_device_id !== auth.deviceId) {
    throw new ApiError("forbidden", "Signer device must be this session", 403);
  }
  const rows = rowsFromBody(body);
  if (!sameMembership(rows, expected)) {
    throw new ApiError("validation", "Membership roster mismatch", 400);
  }
  const signerRole = rows.find((m) => m.userId === body.signer_user_id)?.role;
  if (signerRole !== "admin") throw new ApiError("forbidden", "Signer is not an admin", 403);
  const prior = await loadStoredMembers(db, groupId);
  if (prior) {
    const prevRole = prior.find((m) => m.userId === body.signer_user_id)?.role;
    if (prevRole !== "admin") {
      throw new ApiError("forbidden", "Signer is not a prior admin", 403);
    }
  }
  const pub = await loadSignerEd25519(db, body.signer_user_id, body.signer_device_id);
  const ok = verifyMembership({
    groupId,
    epoch: body.epoch,
    members: rows,
    signerEd25519: pub,
    signature: Buffer.from(body.signature, "base64"),
  });
  if (!ok) throw new ApiError("forbidden", "Membership signature invalid", 403);
  return body;
}

async function persistMembership(db: Db, groupId: string, epoch: number, body: MembershipBody) {
  await db.query(
    `UPDATE groups SET epoch = $2, membership_epoch = $2, membership_json = $3,
     membership_sig = $4, membership_signer_user_id = $5, membership_signer_device_id = $6
     WHERE id = $1`,
    [
      groupId,
      epoch,
      JSON.stringify(body.members),
      Buffer.from(body.signature, "base64"),
      body.signer_user_id,
      body.signer_device_id,
    ],
  );
}

function wireMembership(row: {
  membership_epoch: number | null;
  membership_json: string | null;
  membership_sig: Uint8Array | null;
  membership_signer_user_id: string | null;
  membership_signer_device_id: string | null;
}) {
  if (!row.membership_json || !row.membership_sig || row.membership_epoch == null) return null;
  return {
    epoch: row.membership_epoch,
    members: JSON.parse(row.membership_json) as Array<{ user_id: string; role: string }>,
    signer_user_id: row.membership_signer_user_id,
    signer_device_id: row.membership_signer_device_id,
    signature: Buffer.from(row.membership_sig).toString("base64"),
  };
}

export async function registerGroups(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/groups", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        id: z.string().uuid().optional(),
        member_ids: z.array(z.string().uuid()).max(256),
        membership: membershipBody,
      })
      .parse(req.body ?? {});
    const id = body.id ?? randomUuid();
    const unique = [...new Set([auth.userId, ...body.member_ids])];
    const expected = unique.map((uid) => ({
      userId: uid,
      role: uid === auth.userId ? "admin" : "member",
    }));
    await requireSignedMembership(db, auth, id, body.membership, expected, 1);
    await db.query("INSERT INTO groups (id, creator_id, epoch) VALUES ($1,$2,1)", [id, auth.userId]);
    for (const uid of unique) {
      await db.query(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,$3)`, [
        id,
        uid,
        uid === auth.userId ? "admin" : "member",
      ]);
    }
    await persistMembership(db, id, 1, body.membership);
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
    const g = await db.query<{
      id: string;
      epoch: number;
      creator_id: string;
      membership_epoch: number | null;
      membership_json: string | null;
      membership_sig: Uint8Array | null;
      membership_signer_user_id: string | null;
      membership_signer_device_id: string | null;
    }>(
      `SELECT id, epoch, creator_id, membership_epoch, membership_json, membership_sig,
              membership_signer_user_id, membership_signer_device_id
       FROM groups WHERE id = $1`,
      [id],
    );
    const members = await db.query<{ user_id: string; role: string }>(
      "SELECT user_id, role FROM group_members WHERE group_id = $1 AND removed_at IS NULL",
      [id],
    );
    const row = g.rows[0];
    if (!row) throw new ApiError("not_found", "Group not found", 404);
    const pending = await db.query<{ used_by: string }>(
      `SELECT i.used_by
       FROM group_invites i
       WHERE i.group_id = $1 AND i.used_at IS NOT NULL AND i.used_by IS NOT NULL
         AND NOT EXISTS (
           SELECT 1 FROM group_members m
           WHERE m.group_id = i.group_id AND m.user_id = i.used_by AND m.removed_at IS NULL
         )`,
      [id],
    );
    return {
      group: {
        id: row.id,
        epoch: row.epoch,
        creator_id: row.creator_id,
        members: members.rows,
        pending_joins: pending.rows.map((p) => ({ user_id: p.used_by })),
        membership: wireMembership(row),
      },
    };
  });

  app.post("/v1/groups/:id/members", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const me = await requireMember(db, id, auth.userId);
    if (me.role !== "admin" && me.role !== "moderator") {
      throw new ApiError("forbidden", "Insufficient role", 403);
    }
    const body = z
      .object({
        user_id: z.string().uuid(),
        role: z.enum(["member", "moderator"]).optional(),
        membership: membershipBody,
      })
      .parse(req.body);
    const g = await db.query<{ epoch: number }>("SELECT epoch FROM groups WHERE id = $1", [id]);
    const nextEpoch = (g.rows[0]?.epoch ?? 0) + 1;
    const current = await liveMembers(db, id);
    const expected = current.some((m) => m.userId === body.user_id)
      ? current.map((m) => (m.userId === body.user_id ? { userId: m.userId, role: body.role ?? m.role } : m))
      : [...current, { userId: body.user_id, role: body.role ?? "member" }];
    await requireSignedMembership(db, auth, id, body.membership, expected, nextEpoch);
    await db.query(
      `INSERT INTO group_members (group_id, user_id, role) VALUES ($1,$2,$3)
       ON CONFLICT (group_id, user_id) DO UPDATE SET removed_at = NULL, role = EXCLUDED.role`,
      [id, body.user_id, body.role ?? "member"],
    );
    await persistMembership(db, id, nextEpoch, body.membership);
    return { ok: true, epoch: nextEpoch };
  });

  app.delete("/v1/groups/:id/members/:userId", async (req) => {
    const auth = requireAuth(req);
    const { id, userId } = req.params as { id: string; userId: string };
    const me = await requireMember(db, id, auth.userId);
    if (userId !== auth.userId && me.role !== "admin") {
      throw new ApiError("forbidden", "Insufficient role", 403);
    }
    const body = z.object({ membership: membershipBody }).parse(req.body ?? {});
    const g = await db.query<{ epoch: number }>("SELECT epoch FROM groups WHERE id = $1", [id]);
    const nextEpoch = (g.rows[0]?.epoch ?? 0) + 1;
    const expected = (await liveMembers(db, id)).filter((m) => m.userId !== userId);
    await requireSignedMembership(db, auth, id, body.membership, expected, nextEpoch);
    await db.query("UPDATE group_members SET removed_at = now() WHERE group_id = $1 AND user_id = $2", [
      id,
      userId,
    ]);
    await persistMembership(db, id, nextEpoch, body.membership);
    return { ok: true, epoch: nextEpoch };
  });

  app.post("/v1/groups/:id/epoch", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    await requireMember(db, id, auth.userId);
    const body = z.object({ membership: membershipBody }).parse(req.body ?? {});
    const g = await db.query<{ epoch: number }>("SELECT epoch FROM groups WHERE id = $1", [id]);
    const nextEpoch = (g.rows[0]?.epoch ?? 0) + 1;
    const expected = await liveMembers(db, id);
    await requireSignedMembership(db, auth, id, body.membership, expected, nextEpoch);
    await persistMembership(db, id, nextEpoch, body.membership);
    return { epoch: nextEpoch };
  });

  app.post("/v1/groups/:id/invites", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const me = await requireMember(db, id, auth.userId);
    if (me.role !== "admin") throw new ApiError("forbidden", "Insufficient role", 403);
    const token = randomToken(18);
    const exp = new Date(Date.now() + 7 * 86400_000);
    await db.query(`INSERT INTO group_invites (token_hash, group_id, created_by, expires_at) VALUES ($1,$2,$3,$4)`, [
      sha256Hex(token),
      id,
      auth.userId,
      exp.toISOString(),
    ]);
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
    const g = await db.query<{
      membership_epoch: number | null;
      membership_json: string | null;
      membership_sig: Uint8Array | null;
      membership_signer_user_id: string | null;
      membership_signer_device_id: string | null;
    }>(
      `SELECT membership_epoch, membership_json, membership_sig,
              membership_signer_user_id, membership_signer_device_id
       FROM groups WHERE id = $1`,
      [id],
    );
    const signed = g.rows[0] ? wireMembership(g.rows[0]) : null;
    if (!signed) throw new ApiError("unsigned_membership", "Signed membership required", 400);
    const members = await db.query<{ user_id: string }>(
      "SELECT user_id FROM group_members WHERE group_id = $1 AND removed_at IS NULL",
      [id],
    );
    const recipients = planFanoutRecipients(
      signed.members.map((m) => m.user_id),
      members.rows.map((m) => m.user_id),
    );
    if (!recipients.includes(auth.userId)) {
      throw new ApiError("forbidden", "Not a signed member", 403);
    }
    const expires = body.ttl_seconds
      ? new Date(Date.now() + body.ttl_seconds * 1000).toISOString()
      : new Date(Date.now() + 30 * 86400_000).toISOString();
    let n = 0;
    for (const uid of recipients) {
      const m = { user_id: uid };
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
        if (body.kind === "message" || body.kind === "call") {
          await maybeWake(db, m.user_id, d.id, body.kind === "call" ? "call" : "msg");
        }
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
    const live = await db.query<{ user_id: string }>(
      "SELECT user_id FROM group_members WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
      [inv.group_id, auth.userId],
    );
    const claimed = await db.query<{ group_id: string }>(
      `UPDATE group_invites SET used_at = now(), used_by = $2
       WHERE token_hash = $1 AND used_at IS NULL
       RETURNING group_id`,
      [sha256Hex(token), auth.userId],
    );
    if (!claimed.rows[0]) throw new ApiError("not_found", "Invite not found", 404);
    const epochRow = await db.query<{ epoch: number }>("SELECT epoch FROM groups WHERE id = $1", [inv.group_id]);
    return {
      group_id: inv.group_id,
      epoch: epochRow.rows[0]?.epoch ?? 1,
      pending: live.rows.length === 0,
    };
  });
}
