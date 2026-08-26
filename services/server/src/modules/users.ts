import type { FastifyInstance } from "fastify";
import { isValidUsername, normalizeUsername } from "@ollo/protocol";
import { MAX_USERNAME_CHANGES_PER_DAY } from "@ollo/shared";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { dropUser } from "../realtime/hub.js";
import { randomUuid } from "../security/crypto-utils.js";

function publicUser(row: {
  id: string;
  username: string | null;
  display_name: string;
  about: string;
  avatar_object_id: string | null;
}) {
  return {
    id: row.id,
    username: row.username,
    display_name: row.display_name,
    about: row.about,
    avatar_object_id: row.avatar_object_id,
  };
}

export async function registerUsers(app: FastifyInstance, db: Db): Promise<void> {
  app.get("/v1/me", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{
      id: string;
      username: string | null;
      display_name: string;
      about: string;
      avatar_object_id: string | null;
      deleted_at: string | null;
    }>(
      "SELECT id, username, display_name, about, avatar_object_id, deleted_at FROM users WHERE id = $1",
      [auth.userId],
    );
    if (!r.rows[0] || r.rows[0].deleted_at) throw new ApiError("not_found", "User not found", 404);
    return { user: publicUser(r.rows[0]), device_id: auth.deviceId };
  });

  app.put("/v1/me", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        username: z.string().optional(),
        display_name: z.string().max(64).optional(),
        about: z.string().max(280).optional(),
        avatar_object_id: z.string().nullable().optional(),
      })
      .parse(req.body);
    if (body.username !== undefined) {
      const un = normalizeUsername(body.username);
      if (!isValidUsername(un)) throw new ApiError("validation", "Invalid username");
      const current = await db.query<{ username: string | null }>(
        "SELECT username FROM users WHERE id = $1",
        [auth.userId],
      );
      if ((current.rows[0]?.username ?? null) !== un) {
        const used = await db.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM username_changes
           WHERE user_id = $1 AND changed_at > now() - interval '1 day'`,
          [auth.userId],
        );
        if (Number(used.rows[0]?.n ?? 0) >= MAX_USERNAME_CHANGES_PER_DAY) {
          throw new ApiError("rate_limited", "Too many username changes", 429);
        }
        const clash = await db.query<{ id: string }>(
          "SELECT id FROM users WHERE lower(username) = $1 AND id <> $2",
          [un, auth.userId],
        );
        if (clash.rows[0]) throw new ApiError("conflict", "Username taken", 409);
        await db.query("UPDATE users SET username = $2 WHERE id = $1", [auth.userId, un]);
        await db.query("INSERT INTO username_changes (id, user_id) VALUES ($1,$2)", [
          randomUuid(),
          auth.userId,
        ]);
      }
    }
    if (body.display_name !== undefined) {
      await db.query("UPDATE users SET display_name = $2 WHERE id = $1", [auth.userId, body.display_name]);
    }
    if (body.about !== undefined) {
      await db.query("UPDATE users SET about = $2 WHERE id = $1", [auth.userId, body.about]);
    }
    if (body.avatar_object_id !== undefined) {
      await db.query("UPDATE users SET avatar_object_id = $2 WHERE id = $1", [
        auth.userId,
        body.avatar_object_id,
      ]);
    }
    const r = await db.query<{
      id: string;
      username: string | null;
      display_name: string;
      about: string;
      avatar_object_id: string | null;
    }>("SELECT id, username, display_name, about, avatar_object_id FROM users WHERE id = $1", [
      auth.userId,
    ]);
    return { user: publicUser(r.rows[0]!) };
  });

  app.get("/v1/users/:id", async (req) => {
    requireAuth(req);
    const { id } = req.params as { id: string };
    const r = await db.query<{
      id: string;
      username: string | null;
      display_name: string;
      about: string;
      avatar_object_id: string | null;
    }>(
      "SELECT id, username, display_name, about, avatar_object_id FROM users WHERE id = $1 AND deleted_at IS NULL",
      [id],
    );
    if (!r.rows[0]) throw new ApiError("not_found", "User not found", 404);
    return { user: publicUser(r.rows[0]) };
  });

  app.get("/v1/users/by-username/:name", async (req) => {
    requireAuth(req);
    const name = normalizeUsername((req.params as { name: string }).name);
    const r = await db.query<{
      id: string;
      username: string | null;
      display_name: string;
      about: string;
      avatar_object_id: string | null;
    }>(
      "SELECT id, username, display_name, about, avatar_object_id FROM users WHERE lower(username) = $1 AND deleted_at IS NULL",
      [name],
    );
    if (!r.rows[0]) throw new ApiError("not_found", "User not found", 404);
    return { user: publicUser(r.rows[0]) };
  });

  app.post("/v1/users/search", async (req) => {
    requireAuth(req);
    const body = z.object({ username: z.string().optional(), phone_e164: z.string().optional() }).parse(req.body);
    if (body.phone_e164) {
      throw new ApiError(
        "validation",
        "Phone lookup is not offered; contact discovery is on-device and mutual",
        403,
      );
    }
    if (body.username) {
      const name = normalizeUsername(body.username);
      const r = await db.query<{
        id: string;
        username: string | null;
        display_name: string;
        about: string;
        avatar_object_id: string | null;
      }>(
        "SELECT id, username, display_name, about, avatar_object_id FROM users WHERE lower(username) = $1 AND deleted_at IS NULL",
        [name],
      );
      return { users: r.rows.map(publicUser) };
    }
    throw new ApiError("validation", "username required");
  });

  app.get("/v1/contacts", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{
      id: string;
      username: string | null;
      display_name: string;
      about: string;
      avatar_object_id: string | null;
    }>(
      `SELECT u.id, u.username, u.display_name, u.about, u.avatar_object_id
       FROM contacts c JOIN users u ON u.id = c.contact_user_id
       WHERE c.user_id = $1 AND u.deleted_at IS NULL`,
      [auth.userId],
    );
    return { contacts: r.rows.map(publicUser) };
  });

  app.post("/v1/contacts", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ user_id: z.string().uuid() }).parse(req.body);
    if (body.user_id === auth.userId) throw new ApiError("validation", "Cannot add yourself");
    await db.query(
      `INSERT INTO contacts (user_id, contact_user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [auth.userId, body.user_id],
    );
    return { ok: true };
  });

  app.delete("/v1/contacts/:userId", async (req) => {
    const auth = requireAuth(req);
    await db.query("DELETE FROM contacts WHERE user_id = $1 AND contact_user_id = $2", [
      auth.userId,
      (req.params as { userId: string }).userId,
    ]);
    return { ok: true };
  });

  app.post("/v1/blocks", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ user_id: z.string().uuid() }).parse(req.body);
    await db.query(
      `INSERT INTO blocks (user_id, blocked_user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
      [auth.userId, body.user_id],
    );
    await db.query("DELETE FROM contacts WHERE user_id = $1 AND contact_user_id = $2", [
      auth.userId,
      body.user_id,
    ]);
    return { ok: true };
  });

  app.delete("/v1/blocks/:userId", async (req) => {
    const auth = requireAuth(req);
    await db.query("DELETE FROM blocks WHERE user_id = $1 AND blocked_user_id = $2", [
      auth.userId,
      (req.params as { userId: string }).userId,
    ]);
    return { ok: true };
  });

  app.get("/v1/blocks", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{ blocked_user_id: string }>(
      "SELECT blocked_user_id FROM blocks WHERE user_id = $1",
      [auth.userId],
    );
    return { blocked: r.rows.map((x) => x.blocked_user_id) };
  });

  const reportWindow = new Map<string, { n: number; reset: number }>();
  app.post("/v1/reports", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        user_id: z.string().uuid(),
        reason: z.enum(["spam", "abuse", "other"]),
      })
      .parse(req.body);
    const now = Date.now();
    const cur = reportWindow.get(auth.userId);
    if (!cur || cur.reset < now) {
      reportWindow.set(auth.userId, { n: 1, reset: now + 3_600_000 });
    } else {
      if (cur.n >= 8) throw new ApiError("rate_limited", "Too many reports", 429);
      cur.n += 1;
    }
    await db.query(
      `INSERT INTO reports (id, reporter_id, reportee_id, reason) VALUES ($1,$2,$3,$4)`,
      [randomUuid(), auth.userId, body.user_id, body.reason],
    );
    return { ok: true };
  });

  app.post("/v1/me/delete", async (req) => {
    const auth = requireAuth(req);
    const devices = await db.query<{ id: string }>(
      "SELECT id FROM devices WHERE user_id = $1",
      [auth.userId],
    );
    const ids = devices.rows.map((d) => d.id);
    if (ids.length) {
      await db.query("DELETE FROM one_time_prekeys WHERE device_id = ANY($1::uuid[])", [ids]);
      await db.query(
        "DELETE FROM envelopes WHERE recipient_device_id = ANY($1::uuid[]) OR sender_device_id = ANY($1::uuid[])",
        [ids],
      );
    }
    await db.query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", [
      auth.userId,
    ]);
    await db.query(
      `UPDATE devices SET
         revoked_at = now(),
         push_token_enc = NULL,
         identity_x25519 = $2,
         identity_ed25519 = $2,
         signed_prekey_public = $2,
         signed_prekey_sig = $2
       WHERE user_id = $1`,
      [auth.userId, Buffer.alloc(0)],
    );
    await db.query("DELETE FROM contacts WHERE user_id = $1 OR contact_user_id = $1", [auth.userId]);
    await db.query("DELETE FROM blocks WHERE user_id = $1 OR blocked_user_id = $1", [auth.userId]);
    await db.query("DELETE FROM mutes WHERE user_id = $1", [auth.userId]);
    await db.query("DELETE FROM archives WHERE user_id = $1", [auth.userId]);
    await db.query("DELETE FROM backups WHERE user_id = $1", [auth.userId]);
    await db.query(
      `UPDATE users SET
         deleted_at = now(),
         username = NULL,
         display_name = '',
         about = '',
         avatar_object_id = NULL,
         registration_lock_hash = NULL,
         phone_hmac = $2
       WHERE id = $1`,
      [auth.userId, `deleted:${auth.userId}`],
    );
    dropUser(auth.userId);
    return { ok: true };
  });

  app.post("/v1/threads/mute", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ thread_id: z.string(), until: z.string().nullable().optional() }).parse(req.body);
    await db.query(
      `INSERT INTO mutes (user_id, thread_id, until) VALUES ($1,$2,$3)
       ON CONFLICT (user_id, thread_id) DO UPDATE SET until = EXCLUDED.until`,
      [auth.userId, body.thread_id, body.until ?? null],
    );
    return { ok: true };
  });

  app.post("/v1/threads/archive", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ thread_id: z.string(), archived: z.boolean() }).parse(req.body);
    if (body.archived) {
      await db.query(
        `INSERT INTO archives (user_id, thread_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
        [auth.userId, body.thread_id],
      );
    } else {
      await db.query("DELETE FROM archives WHERE user_id = $1 AND thread_id = $2", [
        auth.userId,
        body.thread_id,
      ]);
    }
    return { ok: true };
  });
}
