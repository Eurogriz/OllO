import type { FastifyInstance } from "fastify";
import { isValidE164 } from "@ollo/protocol";
import { ACCESS_TTL_SECONDS, REFRESH_TTL_SECONDS } from "@ollo/shared";
import { z } from "zod";
import { config } from "../config.js";
import type { Db } from "../db/index.js";
import { ApiError, requireAuth } from "../http.js";
import {
  kdfHash,
  kdfVerify,
  otpCode,
  phoneHmac,
  randomId,
  randomToken,
  randomUuid,
  sha256Hex,
  signAccess,
} from "../security/crypto-utils.js";
import {
  ED25519_PUBLIC_LEN,
  ED25519_SIGNATURE_LEN,
  X25519_PUBLIC_LEN,
  requirePublicBytes,
} from "../security/public-keys.js";

const requestOtpSchema = z.object({
  phone_e164: z.string(),
  device_fingerprint: z.string().max(128).optional(),
});

const verifySchema = z.object({
  challenge_id: z.string(),
  otp: z.string().min(4).max(10),
  registration_lock: z.string().min(4).max(128).nullable().optional(),
  device: z.object({
    name: z.string().min(1).max(64),
    platform: z.enum(["android", "ios", "web", "desktop"]),
    identity_key_x25519: z.string(),
    identity_key_ed25519: z.string(),
    registration_id: z.number().int().nonnegative(),
    signed_prekey: z.object({
      id: z.number().int().positive(),
      public: z.string(),
      signature: z.string(),
    }),
    one_time_prekeys: z
      .array(z.object({ id: z.number().int().positive(), public: z.string() }))
      .min(1)
      .max(200),
  }),
});

const otpWindow = new Map<string, { n: number; reset: number }>();

function takeOtpSlot(phoneH: string): void {
  const now = Date.now();
  const cur = otpWindow.get(phoneH);
  if (!cur || cur.reset < now) {
    otpWindow.set(phoneH, { n: 1, reset: now + 60_000 });
    return;
  }
  if (cur.n >= 3) throw new ApiError("rate_limited", "Too many OTP requests", 429);
  cur.n += 1;
}

export async function registerAuth(app: FastifyInstance, db: Db): Promise<void> {
  app.post("/v1/auth/request-otp", async (req, reply) => {
    const body = requestOtpSchema.parse(req.body);
    if (!isValidE164(body.phone_e164)) {
      throw new ApiError("validation", "Phone must be E.164");
    }
    const ph = phoneHmac(body.phone_e164);
    takeOtpSlot(ph);
    const otp = otpCode(config.otpLength);
    const challengeId = randomId("ch");
    const otpHash = sha256Hex(`${config.otpPepper}:${challengeId}:${otp}`);
    const expires = new Date(Date.now() + config.otpTtlSeconds * 1000);
    await db.query(
      `INSERT INTO otp_challenges (id, phone_hmac, otp_hash, device_fingerprint, expires_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [challengeId, ph, otpHash, body.device_fingerprint ?? null, expires.toISOString()],
    );
    const res: Record<string, unknown> = {
      challenge_id: challengeId,
      expires_in: config.otpTtlSeconds,
    };
    if (config.otpDevReveal && !config.isProd) {
      res.dev_otp = otp;
    }
    return reply.send(res);
  });

  app.post("/v1/auth/verify-otp", async (req, reply) => {
    const body = verifySchema.parse(req.body);
    const ch = await db.query<{
      id: string;
      phone_hmac: string;
      otp_hash: string;
      attempts: number;
      expires_at: string;
      consumed_at: string | null;
    }>("SELECT * FROM otp_challenges WHERE id = $1", [body.challenge_id]);
    const row = ch.rows[0];
    if (!row) throw new ApiError("otp_invalid", "Invalid or expired code");
    if (row.consumed_at) throw new ApiError("otp_invalid", "Invalid or expired code");
    if (new Date(row.expires_at).getTime() < Date.now()) {
      throw new ApiError("otp_expired", "Invalid or expired code");
    }
    if (row.attempts >= config.otpMaxAttempts) {
      throw new ApiError("rate_limited", "Too many attempts", 429);
    }
    const incoming = sha256Hex(`${config.otpPepper}:${body.challenge_id}:${body.otp}`);
    if (incoming !== row.otp_hash) {
      await db.query("UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = $1", [row.id]);
      throw new ApiError("otp_invalid", "Invalid or expired code");
    }
    await db.query("DELETE FROM otp_challenges WHERE id = $1", [row.id]);

    const existing = await db.query<{
      id: string;
      username: string | null;
      registration_lock_hash: string | null;
      deleted_at: string | null;
    }>("SELECT id, username, registration_lock_hash, deleted_at FROM users WHERE phone_hmac = $1", [
      row.phone_hmac,
    ]);

    let userId: string;
    let isNew = false;
    if (!existing.rows[0] || existing.rows[0].deleted_at) {
      userId = randomUuid();
      isNew = true;
      await db.query(
        `INSERT INTO users (id, phone_hmac, display_name) VALUES ($1,$2,'')`,
        [userId, row.phone_hmac],
      );
    } else {
      userId = existing.rows[0].id;
      const lock = existing.rows[0].registration_lock_hash;
      if (lock) {
        if (!body.registration_lock) {
          throw new ApiError("registration_lock", "Registration lock required", 403);
        }
        const ok = await kdfVerify(body.registration_lock, config.registrationLockPepper, lock);
        if (!ok) throw new ApiError("registration_lock", "Registration lock required", 403);
      }
    }

    const deviceId = randomUuid();
    await db.query(
      `INSERT INTO devices (
         id, user_id, name, platform, registration_id,
         identity_x25519, identity_ed25519,
         signed_prekey_id, signed_prekey_public, signed_prekey_sig
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        deviceId,
        userId,
        body.device.name,
        body.device.platform,
        body.device.registration_id,
        requirePublicBytes(body.device.identity_key_x25519, X25519_PUBLIC_LEN, "identity_key_x25519"),
        requirePublicBytes(body.device.identity_key_ed25519, ED25519_PUBLIC_LEN, "identity_key_ed25519"),
        body.device.signed_prekey.id,
        requirePublicBytes(body.device.signed_prekey.public, X25519_PUBLIC_LEN, "signed_prekey.public"),
        requirePublicBytes(body.device.signed_prekey.signature, ED25519_SIGNATURE_LEN, "signed_prekey.signature"),
      ],
    );
    for (const k of body.device.one_time_prekeys) {
      await db.query(
        `INSERT INTO one_time_prekeys (device_id, key_id, public_key) VALUES ($1,$2,$3)`,
        [deviceId, k.id, requirePublicBytes(k.public, X25519_PUBLIC_LEN, "one_time_prekey")],
      );
    }

    const session = await issueSession(db, userId, deviceId);
    const user = await db.query<{ id: string; username: string | null }>(
      "SELECT id, username FROM users WHERE id = $1",
      [userId],
    );
    return reply.send({
      user: { id: userId, username: user.rows[0]?.username ?? null, is_new: isNew },
      device_id: deviceId,
      access_token: session.access,
      refresh_token: session.refresh,
      access_expires_in: ACCESS_TTL_SECONDS,
    });
  });

  app.post("/v1/auth/refresh", async (req, reply) => {
    const body = z.object({ refresh_token: z.string() }).parse(req.body);
    const hash = sha256Hex(body.refresh_token);
    const row = await db.query<{
      id: string;
      user_id: string;
      device_id: string;
      family_id: string;
      expires_at: string;
      revoked_at: string | null;
    }>("SELECT * FROM sessions WHERE refresh_hash = $1", [hash]);
    const s = row.rows[0];
    if (!s) throw new ApiError("unauthorized", "Invalid refresh token", 401);
    if (s.revoked_at || new Date(s.expires_at).getTime() < Date.now()) {
      await db.query(
        `UPDATE sessions SET revoked_at = now(), refresh_hash = 'revoked:' || id
         WHERE family_id = $1 AND refresh_hash NOT LIKE 'revoked:%'`,
        [s.family_id],
      );
      throw new ApiError("unauthorized", "Refresh token reuse detected", 401);
    }
    const next = await issueSession(db, s.user_id, s.device_id, s.family_id);
    await db.query("UPDATE sessions SET revoked_at = now(), replaced_by = $2 WHERE id = $1", [
      s.id,
      next.id,
    ]);
    return reply.send({
      access_token: next.access,
      refresh_token: next.refresh,
      access_expires_in: ACCESS_TTL_SECONDS,
    });
  });

  app.post("/v1/auth/logout", async (req, reply) => {
    const auth = requireAuth(req);
    await db.query(
      `UPDATE sessions SET revoked_at = now(), refresh_hash = 'revoked:' || id
       WHERE device_id = $1 AND refresh_hash NOT LIKE 'revoked:%'`,
      [auth.deviceId],
    );
    return reply.send({ ok: true });
  });

  app.post("/v1/auth/logout-all", async (req, reply) => {
    const auth = requireAuth(req);
    await db.query(
      `UPDATE sessions SET revoked_at = now(), refresh_hash = 'revoked:' || id
       WHERE user_id = $1 AND refresh_hash NOT LIKE 'revoked:%'`,
      [auth.userId],
    );
    return reply.send({ ok: true });
  });

  app.post("/v1/auth/registration-lock", async (req, reply) => {
    const auth = requireAuth(req);
    const body = z
      .object({
        pin: z.string().min(4).max(128).nullable(),
        current_pin: z.string().min(4).max(128).optional(),
      })
      .parse(req.body);
    const u = await db.query<{ registration_lock_hash: string | null }>(
      "SELECT registration_lock_hash FROM users WHERE id = $1",
      [auth.userId],
    );
    const existing = u.rows[0]?.registration_lock_hash;
    if (existing) {
      if (!body.current_pin) throw new ApiError("registration_lock", "Current PIN required", 403);
      const ok = await kdfVerify(body.current_pin, config.registrationLockPepper, existing);
      if (!ok) throw new ApiError("registration_lock", "Current PIN required", 403);
    }
    const next = body.pin ? await kdfHash(body.pin, config.registrationLockPepper) : null;
    await db.query("UPDATE users SET registration_lock_hash = $2 WHERE id = $1", [auth.userId, next]);
    return reply.send({ enabled: Boolean(next) });
  });
}

async function issueSession(db: Db, userId: string, deviceId: string, familyId = randomUuid()) {
  const refresh = randomToken(32);
  const id = randomUuid();
  const exp = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000);
  await db.query(
    `INSERT INTO sessions (id, user_id, device_id, refresh_hash, family_id, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, userId, deviceId, sha256Hex(refresh), familyId, exp.toISOString()],
  );
  const access = signAccess({ sub: userId, did: deviceId }, ACCESS_TTL_SECONDS);
  return { id, access, refresh };
}
