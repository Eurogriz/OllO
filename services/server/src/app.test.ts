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
  });
});
