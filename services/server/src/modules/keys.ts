import type { FastifyInstance } from "fastify";
import { deviceRosterHash, verifySignedPrekey } from "@ollo/crypto";
import { z } from "zod";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import { dropDevice } from "../realtime/hub.js";
import { takeWindow } from "../redis.js";
import {
  ED25519_SIGNATURE_LEN,
  X25519_PUBLIC_LEN,
  requirePublicBytes,
} from "../security/public-keys.js";

function b64(value: unknown): string {
  if (Buffer.isBuffer(value)) return value.toString("base64");
  if (value instanceof Uint8Array) return Buffer.from(value).toString("base64");
  return Buffer.from(value as ArrayBuffer).toString("base64");
}

export async function registerKeys(app: FastifyInstance, db: Db): Promise<void> {
  app.get("/v1/devices", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{
      id: string;
      name: string;
      platform: string;
      created_at: string;
      last_seen_at: string;
      identity_ed25519: Buffer;
      identity_x25519: Buffer;
    }>(
      `SELECT id, name, platform, created_at, last_seen_at, identity_ed25519, identity_x25519
       FROM devices WHERE user_id = $1 AND revoked_at IS NULL`,
      [auth.userId],
    );
    return {
      roster_hash: rosterHash(r.rows),
      devices: r.rows.map((d) => ({
        id: d.id,
        name: d.name,
        platform: d.platform,
        created_at: d.created_at,
        last_seen_at: d.last_seen_at,
        identity_ed25519: b64(d.identity_ed25519),
        this_device: d.id === auth.deviceId,
      })),
    };
  });

  app.delete("/v1/devices/:id", async (req) => {
    const auth = requireAuth(req);
    const id = (req.params as { id: string }).id;
    const r = await db.query<{ user_id: string }>(
      "SELECT user_id FROM devices WHERE id = $1 AND revoked_at IS NULL",
      [id],
    );
    if (!r.rows[0] || r.rows[0].user_id !== auth.userId) {
      throw new ApiError("not_found", "Device not found", 404);
    }
    await db.query(
      `UPDATE devices SET
         revoked_at = now(),
         push_token_enc = NULL,
         identity_x25519 = $2,
         identity_ed25519 = $2,
         signed_prekey_public = $2,
         signed_prekey_sig = $2,
         signed_prekey_xeddsa = $2
       WHERE id = $1`,
      [id, Buffer.alloc(0)],
    );
    await db.query(
      `UPDATE sessions SET revoked_at = now(), refresh_hash = 'revoked:' || id
       WHERE device_id = $1 AND refresh_hash NOT LIKE 'revoked:%'`,
      [id],
    );
    await db.query("DELETE FROM one_time_prekeys WHERE device_id = $1", [id]);
    await db.query("DELETE FROM envelopes WHERE recipient_device_id = $1", [id]);
    await db.query("DELETE FROM drafts WHERE device_id = $1", [id]);
    dropDevice(id);
    return { ok: true };
  });

  app.put("/v1/devices/push-token", async (req) => {
    const auth = requireAuth(req);
    const body = z.object({ token: z.string().min(8).max(4096), platform: z.enum(["android", "ios", "web"]) }).parse(
      req.body,
    );
    const { wrapPushToken } = await import("./notifications.js");
    await db.query("UPDATE devices SET push_token_enc = $2, last_seen_at = now() WHERE id = $1", [
      auth.deviceId,
      wrapPushToken(body.token),
    ]);
    return { ok: true };
  });

  app.get("/v1/me/prekey-depth", async (req) => {
    const auth = requireAuth(req);
    const r = await db.query<{ n: string }>(
      "SELECT count(*)::text AS n FROM one_time_prekeys WHERE device_id = $1 AND consumed_at IS NULL",
      [auth.deviceId],
    );
    return { remaining: Number(r.rows[0]?.n ?? 0) };
  });

  app.get("/v1/safety/:userId", async (req) => {
    requireAuth(req);
    const userId = (req.params as { userId: string }).userId;
    const r = await db.query<{ id: string; identity_x25519: Buffer; identity_ed25519: Buffer }>(
      `SELECT id, identity_x25519, identity_ed25519 FROM devices
       WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at ASC`,
      [userId],
    );
    return {
      user_id: userId,
      roster_hash: rosterHash(r.rows),
      devices: r.rows.map((d) => ({
        device_id: d.id,
        identity_x25519: b64(d.identity_x25519),
        identity_ed25519: b64(d.identity_ed25519),
      })),
    };
  });

  app.get("/v1/keys/:userId/devices", async (req) => {
    requireAuth(req);
    const userId = (req.params as { userId: string }).userId;
    const devices = await listDeviceRows(db, userId);
    return {
      devices: devices.map((d) => ({
        user_id: userId,
        device_id: d.id,
        registration_id: d.registration_id,
        identity_key_x25519: b64(d.identity_x25519),
        identity_key_ed25519: b64(d.identity_ed25519),
        signed_prekey: signedPrekeyJson(d),
      })),
    };
  });

  app.get("/v1/keys/:userId/:deviceId", async (req) => {
    const auth = requireAuth(req);
    const { userId, deviceId } = req.params as { userId: string; deviceId: string };
    const consume = wantsConsume(req.query, true);
    if (consume) await takeOpkSlot(auth.userId, userId);
    const bundle = await takeBundle(db, userId, deviceId, consume);
    if (!bundle) throw new ApiError("not_found", "Device not found", 404);
    return { bundle };
  });

  app.get("/v1/keys/:userId", async (req) => {
    const auth = requireAuth(req);
    const userId = (req.params as { userId: string }).userId;
    const consume = wantsConsume(req.query, false);
    if (consume) await takeOpkSlot(auth.userId, userId);
    const devices = await listDeviceRows(db, userId);
    const bundles = [];
    for (const d of devices) {
      const bundle = await takeBundle(db, userId, d.id, consume);
      if (bundle) bundles.push(bundle);
    }
    return { bundles };
  });

  app.put("/v1/keys/signed-prekey", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        id: z.number().int().positive(),
        public: z.string(),
        signature: z.string(),
        xeddsa: z.string().optional(),
      })
      .parse(req.body);
    const identity = await db.query<{ identity_ed25519: Buffer }>(
      "SELECT identity_ed25519 FROM devices WHERE id = $1 AND revoked_at IS NULL",
      [auth.deviceId],
    );
    const ed = identity.rows[0]?.identity_ed25519;
    if (!ed) throw new ApiError("not_found", "Device not found", 404);
    const pub = requirePublicBytes(body.public, X25519_PUBLIC_LEN, "signed_prekey.public");
    const sig = requirePublicBytes(body.signature, ED25519_SIGNATURE_LEN, "signed_prekey.signature");
    if (!verifySignedPrekey(new Uint8Array(ed), new Uint8Array(pub), new Uint8Array(sig))) {
      throw new ApiError("validation", "signed_prekey.signature is not valid");
    }
    await db.query(
      `UPDATE devices SET signed_prekey_id = $2, signed_prekey_public = $3, signed_prekey_sig = $4,
         signed_prekey_xeddsa = $5
       WHERE id = $1`,
      [
        auth.deviceId,
        body.id,
        pub,
        sig,
        body.xeddsa
          ? requirePublicBytes(body.xeddsa, ED25519_SIGNATURE_LEN, "signed_prekey.xeddsa")
          : null,
      ],
    );
    return { ok: true };
  });

  app.post("/v1/keys/one-time", async (req) => {
    const auth = requireAuth(req);
    const body = z
      .object({ keys: z.array(z.object({ id: z.number().int().positive(), public: z.string() })).max(200) })
      .parse(req.body);
    for (const k of body.keys) {
      await db.query(
        `INSERT INTO one_time_prekeys (device_id, key_id, public_key) VALUES ($1,$2,$3)
         ON CONFLICT (device_id, key_id) DO NOTHING`,
        [auth.deviceId, k.id, requirePublicBytes(k.public, X25519_PUBLIC_LEN, "one_time_prekey")],
      );
    }
    return { ok: true, count: body.keys.length };
  });
}

function wantsConsume(query: unknown, defaultConsume: boolean): boolean {
  const raw = (query as { consume?: string } | undefined)?.consume;
  if (raw === undefined) return defaultConsume;
  return String(raw) !== "0";
}

async function takeOpkSlot(requesterUserId: string, targetUserId: string): Promise<void> {
  const ok = await takeWindow(`opk:${requesterUserId}:${targetUserId}`, 30, 60);
  if (!ok) throw new ApiError("rate_limited", "Too many key fetches", 429);
}

async function consumeOneTime(
  db: Db,
  deviceId: string,
): Promise<{ id: number; public: string } | null> {
  const opk = await db.query<{ key_id: number; public_key: Buffer }>(
    `UPDATE one_time_prekeys AS op
     SET consumed_at = now()
     FROM (
       SELECT device_id, key_id FROM one_time_prekeys
       WHERE device_id = $1 AND consumed_at IS NULL
       ORDER BY key_id ASC
       LIMIT 1
     ) AS pick
     WHERE op.device_id = pick.device_id
       AND op.key_id = pick.key_id
       AND op.consumed_at IS NULL
     RETURNING op.key_id, op.public_key`,
    [deviceId],
  );
  const row = opk.rows[0];
  if (!row) return null;
  await db.query(
    "UPDATE one_time_prekeys SET public_key = $3 WHERE device_id = $1 AND key_id = $2",
    [deviceId, row.key_id, Buffer.alloc(0)],
  );
  return { id: row.key_id, public: b64(row.public_key) };
}

function rosterHash(rows: { id: string; identity_x25519: Buffer }[]): string {
  return deviceRosterHash(
    rows.map((d) => ({
      deviceId: d.id,
      identityX25519: new Uint8Array(d.identity_x25519),
    })),
  );
}

type DeviceKeyRow = {
  id: string;
  registration_id: number;
  identity_x25519: Buffer;
  identity_ed25519: Buffer;
  signed_prekey_id: number;
  signed_prekey_public: Buffer;
  signed_prekey_sig: Buffer;
  signed_prekey_xeddsa: Buffer | null;
};

function signedPrekeyJson(d: {
  signed_prekey_id: number;
  signed_prekey_public: Buffer;
  signed_prekey_sig: Buffer;
  signed_prekey_xeddsa?: Buffer | null;
}) {
  const out: { id: number; public: string; signature: string; xeddsa?: string } = {
    id: d.signed_prekey_id,
    public: b64(d.signed_prekey_public),
    signature: b64(d.signed_prekey_sig),
  };
  if (d.signed_prekey_xeddsa && d.signed_prekey_xeddsa.length > 0) {
    out.xeddsa = b64(d.signed_prekey_xeddsa);
  }
  return out;
}

async function listDeviceRows(db: Db, userId: string) {
  const devices = await db.query<DeviceKeyRow>(
    `SELECT id, registration_id, identity_x25519, identity_ed25519,
            signed_prekey_id, signed_prekey_public, signed_prekey_sig, signed_prekey_xeddsa
     FROM devices WHERE user_id = $1 AND revoked_at IS NULL`,
    [userId],
  );
  return devices.rows;
}

async function takeBundle(db: Db, userId: string, deviceId: string, consume: boolean) {
  const devices = await db.query<DeviceKeyRow>(
    `SELECT id, registration_id, identity_x25519, identity_ed25519,
            signed_prekey_id, signed_prekey_public, signed_prekey_sig, signed_prekey_xeddsa
     FROM devices WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL`,
    [userId, deviceId],
  );
  const d = devices.rows[0];
  if (!d) return null;
  let oneTime: { id: number; public: string } | null = null;
  if (consume) {
    oneTime = await consumeOneTime(db, d.id);
  }
  return {
    user_id: userId,
    device_id: d.id,
    registration_id: d.registration_id,
    identity_key_x25519: b64(d.identity_x25519),
    identity_key_ed25519: b64(d.identity_ed25519),
    signed_prekey: signedPrekeyJson(d),
    one_time_prekey: oneTime,
  };
}
