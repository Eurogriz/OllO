import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { createLocalDevice } from "@ollo/crypto";
import { beginSession, encryptFirstMessage } from "@ollo/crypto";
import { encodeSealed, paddingBucket } from "@ollo/protocol";

process.env.OLLO_ENV = "development";
process.env.OTP_DEV_REVEAL = "true";
process.env.PGLITE_DATA_DIR = mkdtempSync(join(tmpdir(), "ollo-test-"));
process.env.PHONE_HMAC_PEPPER = "test-phone-pepper";
process.env.SESSION_SIGNING_KEY = "test-session-key";
process.env.OTP_PEPPER = "test-otp-pepper";

const { getDb, closeDb } = await import("./db/index.js");
const { buildApp } = await import("./app.js");

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function devicePayload(name: string) {
  const mat = createLocalDevice();
  return {
    mat,
    json: {
      name,
      platform: "web" as const,
      registration_id: mat.registrationId,
      identity_key_x25519: b64(mat.identity.x25519Public),
      identity_key_ed25519: b64(mat.identity.ed25519Public),
      signed_prekey: {
        id: mat.signedPrekey.id,
        public: b64(mat.signedPrekey.publicKey),
        signature: b64(mat.signedPrekey.signature),
      },
      one_time_prekeys: mat.oneTimePrekeys.slice(0, 10).map((k) => ({
        id: k.id,
        public: b64(k.publicKey),
      })),
    },
  };
}

describe("API integration", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  const dir = process.env.PGLITE_DATA_DIR!;

  before(async () => {
    const db = await getDb();
    app = await buildApp(db);
  });

  after(async () => {
    await app.close();
    await closeDb();
    rmSync(dir, { recursive: true, force: true });
  });

  async function json(
    method: "GET" | "POST" | "PUT" | "DELETE",
    url: string,
    body?: Record<string, unknown>,
    token?: string,
  ) {
    const res = await app.inject({
      method,
      url,
      payload: body,
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
    });
    return { status: res.statusCode, body: res.json() as Record<string, unknown> };
  }

  it("health is up", async () => {
    const res = await app.inject({ method: "GET", url: "/healthz" });
    assert.equal(res.statusCode, 200);
    assert.equal(res.json().ok, true);
  });

  it("registers two users and delivers an E2EE envelope the server cannot read", async () => {
    const aDev = devicePayload("alice-web");
    const bDev = devicePayload("bob-web");

    const otpA = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000001" });
    assert.equal(otpA.status, 200);
    const alice = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpA.body.challenge_id,
      otp: otpA.body.dev_otp,
      device: aDev.json,
    });
    assert.equal(alice.status, 200, JSON.stringify(alice.body));

    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000002" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      device: bDev.json,
    });
    assert.equal(bob.status, 200, JSON.stringify(bob.body));

    const aliceTok = alice.body.access_token as string;
    const bobTok = bob.body.access_token as string;
    const aliceUser = (alice.body.user as { id: string }).id;
    const bobUser = (bob.body.user as { id: string }).id;
    const bobDevice = bob.body.device_id as string;

    await json("PUT", "/v1/me", { username: "alice", display_name: "Алиса" }, aliceTok);
    await json("PUT", "/v1/me", { username: "bob", display_name: "Боб" }, bobTok);

    const found = await json("POST", "/v1/users/search", { username: "bob" }, aliceTok);
    assert.equal(((found.body.users as { username: string }[])[0]).username, "bob");

    const keys = await json("GET", `/v1/keys/${bobUser}`, undefined, aliceTok);
    const bundles = keys.body.bundles as Array<{
      user_id: string;
      device_id: string;
      registration_id: number;
      identity_key_x25519: string;
      identity_key_ed25519: string;
      signed_prekey: { id: number; public: string; signature: string };
      one_time_prekey: { id: number; public: string } | null;
    }>;
    assert.ok(bundles.length >= 1);

    const bundle = bundles[0]!;
    const local = { ...aDev.mat, userId: aliceUser, deviceId: alice.body.device_id as string };
    const init = beginSession(local, {
      userId: bundle.user_id,
      deviceId: bundle.device_id,
      registrationId: bundle.registration_id,
      identityKeyX25519: Buffer.from(bundle.identity_key_x25519, "base64"),
      identityKeyEd25519: Buffer.from(bundle.identity_key_ed25519, "base64"),
      signedPrekey: {
        id: bundle.signed_prekey.id,
        publicKey: Buffer.from(bundle.signed_prekey.public, "base64"),
        signature: Buffer.from(bundle.signed_prekey.signature, "base64"),
      },
      oneTimePrekey: bundle.one_time_prekey
        ? {
            id: bundle.one_time_prekey.id,
            publicKey: Buffer.from(bundle.one_time_prekey.public, "base64"),
          }
        : undefined,
    });
    const sealed = encryptFirstMessage(local, init, {
      version: 1,
      type: "text",
      clientId: crypto.randomUUID(),
      sentAt: new Date().toISOString(),
      threadId: bobUser,
      text: "секретное сообщение",
    });
    const payload = encodeSealed(sealed);
    const sent = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            recipient_user_id: bobUser,
            recipient_device_id: bobDevice,
            kind: "message",
            ciphertext: Buffer.from(payload).toString("base64"),
            padding_bucket: paddingBucket(payload.length),
          },
        ],
      },
      aliceTok,
    );
    assert.equal(sent.status, 200, JSON.stringify(sent.body));

    const box = await json("GET", "/v1/envelopes?limit=20", undefined, bobTok);
    const envs = box.body.envelopes as Array<{ ciphertext: string }>;
    assert.ok(envs.length >= 1);
    const ct = Buffer.from(envs[0]!.ciphertext, "base64").toString("utf8");
    assert.equal(ct.includes("секретное сообщение"), false);

    const depthBefore = await json("GET", "/v1/me/prekey-depth", undefined, bobTok);
    const listed = await json("GET", `/v1/keys/${bobUser}?consume=0`, undefined, aliceTok);
    assert.equal(listed.status, 200);
    const listedBundles = listed.body.bundles as Array<{ one_time_prekey: unknown }>;
    assert.equal(listedBundles[0]?.one_time_prekey, null);
    const depthAfter = await json("GET", "/v1/me/prekey-depth", undefined, bobTok);
    assert.equal(depthAfter.body.remaining, depthBefore.body.remaining);

    const presence = await json("GET", `/v1/presence/${bobUser}`, undefined, aliceTok);
    assert.equal(presence.status, 200);
    assert.ok(presence.body.state === "online" || presence.body.state === "offline");
  });

  it("fans out one group ciphertext the server cannot read", async () => {
    const { createSenderKey, distributeSenderKey, encryptGroupMessage, decryptGroupMessage, acceptSenderKey } =
      await import("@ollo/crypto");
    const { encodeSealed, decodeSealed, paddingBucket } = await import("@ollo/protocol");

    const aDev = devicePayload("alice-g");
    const bDev = devicePayload("bob-g");
    const cDev = devicePayload("carol-g");

    async function signup(phone: string, username: string, dev: ReturnType<typeof devicePayload>) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        device: dev.json,
      });
      assert.equal(verified.status, 200, JSON.stringify(verified.body));
      const tok = verified.body.access_token as string;
      await json("PUT", "/v1/me", { username, display_name: username }, tok);
      return {
        tok,
        userId: (verified.body.user as { id: string }).id,
        deviceId: verified.body.device_id as string,
      };
    }

    const alice = await signup("+79990000011", "aliceg", aDev);
    const bob = await signup("+79990000012", "bobg", bDev);
    const carol = await signup("+79990000013", "carolg", cDev);

    const created = await json("POST", "/v1/groups", { member_ids: [bob.userId, carol.userId] }, alice.tok);
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const groupId = (created.body.group as { id: string; epoch: number }).id;
    const epoch = (created.body.group as { epoch: number }).epoch;

    const sk = createSenderKey(groupId, epoch);
    const dist = distributeSenderKey(sk, aDev.mat.identity);
    const bobRemote = acceptSenderKey({
      dist,
      identitySignature: dist.identitySignature,
      senderIdentityEd25519: aDev.mat.identity.ed25519Public,
      userId: alice.userId,
      deviceId: alice.deviceId,
    });
    const sealed = encryptGroupMessage(sk, {
      version: 1,
      type: "text",
      clientId: crypto.randomUUID(),
      sentAt: new Date().toISOString(),
      threadId: groupId,
      text: "группа секрет",
    });
    const payload = encodeSealed(sealed);
    const fan = await json(
      "POST",
      `/v1/groups/${groupId}/fanout`,
      {
        kind: "message",
        ciphertext: Buffer.from(payload).toString("base64"),
        padding_bucket: paddingBucket(payload.length),
      },
      alice.tok,
    );
    assert.equal(fan.status, 200, JSON.stringify(fan.body));
    assert.equal((fan.body.accepted as number) >= 2, true);

    const outsider = await json(
      "POST",
      `/v1/groups/${groupId}/fanout`,
      {
        kind: "message",
        ciphertext: Buffer.from(payload).toString("base64"),
        padding_bucket: paddingBucket(payload.length),
      },
      carol.tok,
    );
    assert.equal(outsider.status, 200);

    const box = await json("GET", "/v1/envelopes?limit=20", undefined, bob.tok);
    const envs = box.body.envelopes as Array<{ ciphertext: string; group_id: string }>;
    const groupEnv = envs.find((e) => e.group_id === groupId);
    assert.ok(groupEnv);
    const raw = Buffer.from(groupEnv!.ciphertext, "base64");
    assert.equal(raw.toString("utf8").includes("группа секрет"), false);
    const opened = decryptGroupMessage(bobRemote, decodeSealed(raw));
    assert.equal(opened.text, "группа секрет");

    const eveOtp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000014" });
    const eve = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: eveOtp.body.challenge_id,
      otp: eveOtp.body.dev_otp,
      device: devicePayload("eve-g").json,
    });
    const forbidden = await json(
      "POST",
      `/v1/groups/${groupId}/fanout`,
      {
        kind: "message",
        ciphertext: Buffer.from(payload).toString("base64"),
        padding_bucket: paddingBucket(payload.length),
      },
      eve.body.access_token as string,
    );
    assert.equal(forbidden.status, 403);
  });

  it("issues call rooms without SDP and rejects blocked callees", async () => {
    async function signup(phone: string, username: string) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        device: devicePayload(username).json,
      });
      await json("PUT", "/v1/me", { username, display_name: username }, verified.body.access_token as string);
      return {
        tok: verified.body.access_token as string,
        userId: (verified.body.user as { id: string }).id,
      };
    }
    const alice = await signup("+79990000021", "alicecall");
    const bob = await signup("+79990000022", "bobcall");
    const eve = await signup("+79990000023", "evecall");

    const created = await json(
      "POST",
      "/v1/calls",
      { media: "audio", participant_user_ids: [bob.userId] },
      alice.tok,
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const callId = created.body.call_id as string;
    assert.ok(Array.isArray(created.body.ice_servers));
    assert.equal(JSON.stringify(created.body).includes("sdp"), false);

    const joined = await json("POST", `/v1/calls/${callId}/join`, {}, bob.tok);
    assert.equal(joined.status, 200, JSON.stringify(joined.body));

    const peek = await json("GET", `/v1/calls/${callId}`, undefined, eve.tok);
    assert.equal(peek.status, 403);

    await json("POST", "/v1/blocks", { user_id: bob.userId }, alice.tok);
    const blocked = await json(
      "POST",
      "/v1/calls",
      { media: "video", participant_user_ids: [bob.userId] },
      alice.tok,
    );
    assert.equal(blocked.status, 403);
  });

  it("stores an opaque backup and wakes with a sealed payload only", async () => {
    const { sealBackup, encodeBackup } = await import("@ollo/crypto");
    const { recentWakes, resetWakes } = await import("./modules/notifications.js");
    resetWakes();

    const aDev = devicePayload("alice-b");
    const bDev = devicePayload("bob-b");
    const otpA = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000031" });
    const alice = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpA.body.challenge_id,
      otp: otpA.body.dev_otp,
      device: aDev.json,
    });
    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000032" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      device: bDev.json,
    });
    const aliceTok = alice.body.access_token as string;
    const bobTok = bob.body.access_token as string;
    const bobUser = (bob.body.user as { id: string }).id;
    const bobDevice = bob.body.device_id as string;

    const blob = encodeBackup(sealBackup("backup-pass-ok", new TextEncoder().encode("SECRET-IDENTITY-MATERIAL")));
    const put = await json("PUT", "/v1/backups", { blob: Buffer.from(blob).toString("base64") }, aliceTok);
    assert.equal(put.status, 200, JSON.stringify(put.body));
    const got = await json("GET", "/v1/backups/latest", undefined, aliceTok);
    assert.equal(got.status, 200);
    const stored = Buffer.from(got.body.blob as string, "base64").toString("utf8");
    assert.equal(stored.includes("SECRET-IDENTITY-MATERIAL"), false);

    await json("PUT", "/v1/devices/push-token", { token: "fcm-token-not-a-secret-enough", platform: "web" }, bobTok);
    const local = { ...aDev.mat, userId: (alice.body.user as { id: string }).id, deviceId: alice.body.device_id as string };
    const keys = await json("GET", `/v1/keys/${bobUser}/${bobDevice}`, undefined, aliceTok);
    const bundle = keys.body.bundle as {
      user_id: string;
      device_id: string;
      registration_id: number;
      identity_key_x25519: string;
      identity_key_ed25519: string;
      signed_prekey: { id: number; public: string; signature: string };
      one_time_prekey: { id: number; public: string } | null;
    };
    const init = beginSession(local, {
      userId: bundle.user_id,
      deviceId: bundle.device_id,
      registrationId: bundle.registration_id,
      identityKeyX25519: Buffer.from(bundle.identity_key_x25519, "base64"),
      identityKeyEd25519: Buffer.from(bundle.identity_key_ed25519, "base64"),
      signedPrekey: {
        id: bundle.signed_prekey.id,
        publicKey: Buffer.from(bundle.signed_prekey.public, "base64"),
        signature: Buffer.from(bundle.signed_prekey.signature, "base64"),
      },
      oneTimePrekey: bundle.one_time_prekey
        ? { id: bundle.one_time_prekey.id, publicKey: Buffer.from(bundle.one_time_prekey.public, "base64") }
        : undefined,
    });
    const sealed = encryptFirstMessage(local, init, {
      version: 1,
      type: "text",
      clientId: crypto.randomUUID(),
      sentAt: new Date().toISOString(),
      threadId: bobUser,
      text: "не в пуше",
    });
    const payload = encodeSealed(sealed);
    const sent = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            recipient_user_id: bobUser,
            recipient_device_id: bobDevice,
            kind: "message",
            ciphertext: Buffer.from(payload).toString("base64"),
            padding_bucket: paddingBucket(payload.length),
          },
        ],
      },
      aliceTok,
    );
    assert.equal(sent.status, 200, JSON.stringify(sent.body));
    const wakes = recentWakes();
    assert.ok(wakes.length >= 1);
    const last = wakes[wakes.length - 1]!;
    assert.deepEqual(Object.keys(last.payload).sort(), ["t", "v"]);
    assert.equal(last.payload.v, 1);
    assert.equal(last.payload.t, "msg");
    assert.equal(JSON.stringify(last.payload).includes("не в пуше"), false);
  });
});
