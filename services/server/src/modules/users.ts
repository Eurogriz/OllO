import type { FastifyInstance } from "fastify";
import { isValidUsername, normalizeUsername } from "@ollo/protocol";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { phoneHmac, randomUuid } from "../security/crypto-utils.js";

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
    }>("SELECT id, username, display_name, about, avatar_object_id FROM users WHERE id = $1", [
      auth.userId,
    ]);
    if (!r.rows[0]) throw new ApiError("not_found", "User not found", 404);
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
      const clash = await db.query<{ id: string }>(
        "SELECT id FROM users WHERE lower(username) = $1 AND id <> $2",
        [un, auth.userId],
      );
      if (clash.rows[0]) throw new ApiError("conflict", "Username taken", 409);
      await db.query("UPDATE users SET username = $2 WHERE id = $1", [auth.userId, un]);
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
    if (body.phone_e164) {
      const r = await db.query<{
        id: string;
        username: string | null;
        display_name: string;
        about: string;
        avatar_object_id: string | null;
      }>(
        "SELECT id, username, display_name, about, avatar_object_id FROM users WHERE phone_hmac = $1 AND deleted_at IS NULL",
        [phoneHmac(body.phone_e164)],
      );
      return { users: r.rows.map(publicUser) };
    }
    throw new ApiError("validation", "username or phone_e164 required");
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

  app.post("/v1/reports", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ user_id: z.string().uuid(), reason: z.string().min(1).max(500) }).parse(req.body);
    await db.query(
      `INSERT INTO reports (id, reporter_id, reportee_id, reason) VALUES ($1,$2,$3,$4)`,
      [randomUuid(), auth.userId, body.user_id, body.reason],
    );
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
