import type { FastifyInstance, FastifyRequest } from "fastify";
import { verify, verifySignedPrekey } from "@ollo/crypto";
import { isValidE164 } from "@ollo/protocol";
import {
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
  encodeAuthProof,
  planAccountProofKey,
  planAuthProofAccept,
} from "@ollo/shared";
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

const deviceSchema = z.object({
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
});

const verifySchema = z.object({
  challenge_id: z.string(),
  otp: z.string().min(4).max(10),
  registration_lock: z.string().min(4).max(128).nullable().optional(),
  device: deviceSchema,
});

const otpWindow = new Map<string, { n: number; reset: number }>();
const authWindow = new Map<string, { n: number; reset: number }>();

/** Per-IP caps for key-rooted signup. A global slot would DoS every honest client. */
export const AUTH_CHALLENGE_PER_IP = 30;
export const AUTH_REGISTER_PER_IP = 10;

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

function clientIp(req: FastifyRequest): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) {
    return forwarded.split(",")[0]!.trim();
  }
  if (Array.isArray(forwarded) && forwarded[0]) return forwarded[0].split(",")[0]!.trim();
  return req.ip || "unknown";
}

function takeAuthSlot(req: FastifyRequest, action: "challenge" | "register-key"): void {
  const max = action === "challenge" ? AUTH_CHALLENGE_PER_IP : AUTH_REGISTER_PER_IP;
  const key = `${action}:${clientIp(req)}`;
  const now = Date.now();
  const cur = authWindow.get(key);
  if (!cur || cur.reset < now) {
    authWindow.set(key, { n: 1, reset: now + 60_000 });
    return;
  }
  if (cur.n >= max) throw new ApiError("rate_limited", "Too many auth requests", 429);
  cur.n += 1;
}

type DeviceBody = z.infer<typeof deviceSchema>;

function parseDeviceKeys(device: DeviceBody) {
  const identityX = requirePublicBytes(device.identity_key_x25519, X25519_PUBLIC_LEN, "identity_key_x25519");
  const identityEd = requirePublicBytes(device.identity_key_ed25519, ED25519_PUBLIC_LEN, "identity_key_ed25519");
  const spkPub = requirePublicBytes(device.signed_prekey.public, X25519_PUBLIC_LEN, "signed_prekey.public");
  const spkSig = requirePublicBytes(device.signed_prekey.signature, ED25519_SIGNATURE_LEN, "signed_prekey.signature");
  if (!verifySignedPrekey(new Uint8Array(identityEd), new Uint8Array(spkPub), new Uint8Array(spkSig))) {
    throw new ApiError("validation", "signed_prekey.signature is not valid");
  }
  return { identityX, identityEd, spkPub, spkSig };
}

async function insertDevice(db: Db, userId: string, deviceId: string, device: DeviceBody): Promise<void> {
  const keys = parseDeviceKeys(device);
  await db.query(
    `INSERT INTO devices (
       id, user_id, name, platform, registration_id,
       identity_x25519, identity_ed25519,
       signed_prekey_id, signed_prekey_public, signed_prekey_sig
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      deviceId,
      userId,
      device.name,
      device.platform,
      device.registration_id,
      keys.identityX,
      keys.identityEd,
      device.signed_prekey.id,
      keys.spkPub,
      keys.spkSig,
    ],
  );
  for (const k of device.one_time_prekeys) {
    await db.query(
      `INSERT INTO one_time_prekeys (device_id, key_id, public_key) VALUES ($1,$2,$3)`,
      [deviceId, k.id, requirePublicBytes(k.public, X25519_PUBLIC_LEN, "one_time_prekey")],
    );
  }
}

async function attachAccountKey(db: Db, userId: string, identityEd: Buffer): Promise<void> {
  await db.query(
    `UPDATE users SET account_ed25519 = $2 WHERE id = $1 AND account_ed25519 IS NULL`,
    [userId, identityEd],
  );
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

  app.post("/v1/auth/challenge", async (req, reply) => {
    takeAuthSlot(req, "challenge");
    const challengeId = randomId("ch");
    const nonce = randomToken(24);
    const expires = new Date(Date.now() + config.otpTtlSeconds * 1000);
    await db.query(
      `INSERT INTO auth_challenges (id, nonce, expires_at) VALUES ($1,$2,$3)`,
      [challengeId, nonce, expires.toISOString()],
    );
    return reply.send({
      challenge_id: challengeId,
      nonce,
      expires_in: config.otpTtlSeconds,
    });
  });

  app.post("/v1/auth/register-key", async (req, reply) => {
    const body = z
      .object({
        challenge_id: z.string(),
        account_ed25519: z.string(),
        signature: z.string(),
        registration_lock: z.string().min(4).max(128).nullable().optional(),
        device: deviceSchema,
      })
      .parse(req.body);
    takeAuthSlot(req, "register-key");
    const ch = await db.query<{
      id: string;
      nonce: string;
      expires_at: string;
      consumed_at: string | null;
    }>("SELECT * FROM auth_challenges WHERE id = $1", [body.challenge_id]);
    const row = ch.rows[0];
    if (!row) throw new ApiError("unauthorized", "Invalid or expired challenge", 401);
    const keys = parseDeviceKeys(body.device);
    const accountEd = requirePublicBytes(body.account_ed25519, ED25519_PUBLIC_LEN, "account_ed25519");
    if (
      planAccountProofKey({
        accountEd25519: new Uint8Array(accountEd),
        deviceEd25519: new Uint8Array(keys.identityEd),
      }) !== "accept"
    ) {
      throw new ApiError("validation", "Invalid account key");
    }
    const proof = encodeAuthProof(body.challenge_id, row.nonce);
    const sig = requirePublicBytes(body.signature, ED25519_SIGNATURE_LEN, "signature");
    const signatureValid = proof.length > 0 && verify(new Uint8Array(accountEd), proof, new Uint8Array(sig));
    const decision = planAuthProofAccept({
      challengeId: body.challenge_id,
      nonce: row.nonce,
      signatureValid,
      expired: new Date(row.expires_at).getTime() < Date.now(),
      consumed: Boolean(row.consumed_at),
    });
    if (decision !== "accept") throw new ApiError("unauthorized", "Invalid or expired challenge", 401);
    await db.query("DELETE FROM auth_challenges WHERE id = $1", [row.id]);

    const existing = await db.query<{
      id: string;
      username: string | null;
      registration_lock_hash: string | null;
      deleted_at: string | null;
    }>(
      "SELECT id, username, registration_lock_hash, deleted_at FROM users WHERE account_ed25519 = $1",
      [accountEd],
    );
    let userId: string;
    let isNew = false;
    if (!existing.rows[0] || existing.rows[0].deleted_at) {
      userId = randomUuid();
      isNew = true;
      await db.query(
        `INSERT INTO users (id, phone_hmac, display_name, account_ed25519) VALUES ($1,NULL,'',$2)`,
        [userId, accountEd],
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
    await insertDevice(db, userId, deviceId, body.device);
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
    const keys = parseDeviceKeys(body.device);
    await insertDevice(db, userId, deviceId, body.device);
    await attachAccountKey(db, userId, keys.identityEd);

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
