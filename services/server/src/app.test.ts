import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { beginSession, createLocalDevice, encryptFirstMessage, generateEd25519, sign, signMembership } from "@ollo/crypto";
import { encodeSealed, paddingBucket } from "@ollo/protocol";
import { encodeAuthProof, encodeUserUri } from "@ollo/shared";

process.env.OLLO_ENV = "development";
process.env.OTP_DEV_REVEAL = "true";
process.env.RATE_LIMIT_MAX = "1000";
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

  it("does not send X-Frame-Options DENY in development", async () => {
    const res = await app.inject({ method: "GET", url: "/healthz" });
    assert.equal(res.headers["x-frame-options"], undefined);
    const csp = String(res.headers["content-security-policy"] ?? "");
    assert.match(csp, /frame-ancestors/);
    assert.equal(csp.includes("'none'"), false);
    assert.match(csp, /e2b\.app/);
  });

  it("registers two users and delivers an E2EE envelope the server cannot read", async () => {
    const aDev = devicePayload("alice-web");
    const bDev = devicePayload("bob-web");

    const otpA = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000001" });
    assert.equal(otpA.status, 200);
    const alice = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpA.body.challenge_id,
      otp: otpA.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: aDev.json,
    });
    assert.equal(alice.status, 200, JSON.stringify(alice.body));
    const otpGone = await (await getDb()).query<{ id: string }>(
      "SELECT id FROM otp_challenges WHERE id = $1",
      [otpA.body.challenge_id],
    );
    assert.equal(otpGone.rows.length, 0);

    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000002" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
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
    const envs = box.body.envelopes as Array<{ id: string; ciphertext: string }>;
    assert.ok(envs.length >= 1);
    const ct = Buffer.from(envs[0]!.ciphertext, "base64").toString("utf8");
    assert.equal(ct.includes("секретное сообщение"), false);
    const acked = await json("POST", "/v1/envelopes/ack", { ids: [envs[0]!.id] }, bobTok);
    assert.equal(acked.status, 200, JSON.stringify(acked.body));
    const db = await getDb();
    const leftover = await db.query<{ id: string }>("SELECT id FROM envelopes WHERE id = $1", [envs[0]!.id]);
    assert.equal(leftover.rows.length, 0);

    const depthBefore = await json("GET", "/v1/me/prekey-depth", undefined, bobTok);
    const listed = await json("GET", `/v1/keys/${bobUser}?consume=0`, undefined, aliceTok);
    assert.equal(listed.status, 200);
    const listedBundles = listed.body.bundles as Array<{ one_time_prekey: unknown }>;
    assert.equal(listedBundles[0]?.one_time_prekey, null);
    const depthAfter = await json("GET", "/v1/me/prekey-depth", undefined, bobTok);
    assert.equal(depthAfter.body.remaining, depthBefore.body.remaining);

    const leaked = await app.inject({ method: "GET", url: `/v1/me?access_token=${encodeURIComponent(aliceTok)}` });
    assert.equal(leaked.statusCode, 401);
    const me = await json("GET", "/v1/me", undefined, aliceTok);
    assert.equal(me.status, 200);

    const stranger = await json("GET", `/v1/presence/${bobUser}`, undefined, aliceTok);
    assert.equal(stranger.status, 200);
    assert.equal(stranger.body.state, "offline");
    assert.equal(stranger.body.last_seen_day, null);

    const added = await json("POST", "/v1/contacts", { user_id: bobUser }, aliceTok);
    assert.equal(added.status, 200, JSON.stringify(added.body));
    const presence = await json("GET", `/v1/presence/${bobUser}`, undefined, aliceTok);
    assert.equal(presence.status, 200);
    assert.ok(presence.body.state === "online" || presence.body.state === "offline");
  });

  it("fans out one group ciphertext the server cannot read", async () => {
    const {
      createSenderKey,
      distributeSenderKey,
      encryptGroupMessage,
      decryptGroupMessage,
      acceptSenderKey,
      signMembership,
    } = await import("@ollo/crypto");
    const { encodeSealed, decodeSealed, paddingBucket } = await import("@ollo/protocol");

    const aDev = devicePayload("alice-g");
    const bDev = devicePayload("bob-g");
    const cDev = devicePayload("carol-g");

    async function signup(phone: string, username: string, dev: ReturnType<typeof devicePayload>) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
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

    const unsigned = await json("POST", "/v1/groups", { member_ids: [bob.userId, carol.userId] }, alice.tok);
    assert.equal(unsigned.status, 400);

    const groupId = crypto.randomUUID();
    const signedMembers = [
      { userId: alice.userId, role: "admin" as const },
      { userId: bob.userId, role: "member" as const },
      { userId: carol.userId, role: "member" as const },
    ];
    const signed = signMembership({ groupId, epoch: 1, members: signedMembers }, aDev.mat.identity);
    const created = await json(
      "POST",
      "/v1/groups",
      {
        id: groupId,
        member_ids: [bob.userId, carol.userId],
        membership: {
          epoch: 1,
          members: signed.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: alice.userId,
          signer_device_id: alice.deviceId,
          signature: Buffer.from(signed.signature).toString("base64"),
        },
      },
      alice.tok,
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));
    assert.equal((created.body.group as { id: string }).id, groupId);
    const epoch = (created.body.group as { epoch: number }).epoch;
    const peeked = await json("GET", `/v1/groups/${groupId}`, undefined, alice.tok);
    assert.equal(peeked.status, 200, JSON.stringify(peeked.body));
    assert.equal(((peeked.body.group as { membership: { epoch: number } }).membership).epoch, 1);

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
      account_ed25519: b64(generateEd25519().publicKey),
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

    const injected = await json(
      "POST",
      `/v1/groups/${groupId}/members`,
      { user_id: (eve.body.user as { id: string }).id },
      alice.tok,
    );
    assert.equal(injected.status, 400);

    const memberBump = signMembership({ groupId, epoch: 2, members: signedMembers }, bDev.mat.identity);
    const asMember = await json(
      "POST",
      `/v1/groups/${groupId}/epoch`,
      {
        membership: {
          epoch: 2,
          members: memberBump.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: bob.userId,
          signer_device_id: bob.deviceId,
          signature: Buffer.from(memberBump.signature).toString("base64"),
        },
      },
      bob.tok,
    );
    assert.equal(asMember.status, 403);

    const adminBump = signMembership({ groupId, epoch: 2, members: signedMembers }, aDev.mat.identity);
    const bumped = await json(
      "POST",
      `/v1/groups/${groupId}/epoch`,
      {
        membership: {
          epoch: 2,
          members: adminBump.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: alice.userId,
          signer_device_id: alice.deviceId,
          signature: Buffer.from(adminBump.signature).toString("base64"),
        },
      },
      alice.tok,
    );
    assert.equal(bumped.status, 200, JSON.stringify(bumped.body));
    assert.equal(bumped.body.epoch, 2);
    const after = await json("GET", `/v1/groups/${groupId}`, undefined, alice.tok);
    assert.equal((after.body.group as { epoch: number }).epoch, 2);
    assert.equal(((after.body.group as { membership: { epoch: number } }).membership).epoch, 2);
  });

  it("keeps invite-join pending until an admin re-signs", async () => {
    const aDev = devicePayload("alice-inv");
    const bDev = devicePayload("bob-inv");
    const eDev = devicePayload("eve-inv");

    async function signup(phone: string, username: string, dev: ReturnType<typeof devicePayload>) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
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

    const alice = await signup("+79990000071", "aliceinv", aDev);
    const bob = await signup("+79990000072", "bobinv", bDev);
    const eve = await signup("+79990000073", "eveinv", eDev);
    const groupId = crypto.randomUUID();
    const signed = signMembership(
      {
        groupId,
        epoch: 1,
        members: [
          { userId: alice.userId, role: "admin" },
          { userId: bob.userId, role: "member" },
        ],
      },
      aDev.mat.identity,
    );
    const created = await json(
      "POST",
      "/v1/groups",
      {
        id: groupId,
        member_ids: [bob.userId],
        membership: {
          epoch: 1,
          members: signed.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: alice.userId,
          signer_device_id: alice.deviceId,
          signature: Buffer.from(signed.signature).toString("base64"),
        },
      },
      alice.tok,
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));

    const invite = await json("POST", `/v1/groups/${groupId}/invites`, {}, alice.tok);
    assert.equal(invite.status, 200, JSON.stringify(invite.body));
    const joined = await json("POST", `/v1/groups/join/${invite.body.token as string}`, {}, eve.tok);
    assert.equal(joined.status, 200, JSON.stringify(joined.body));
    assert.equal(joined.body.pending, true);
    assert.equal(joined.body.epoch, 1);

    const evePeek = await json("GET", `/v1/groups/${groupId}`, undefined, eve.tok);
    assert.equal(evePeek.status, 403);
    const peeked = await json("GET", `/v1/groups/${groupId}`, undefined, alice.tok);
    const group = peeked.body.group as {
      epoch: number;
      members: { user_id: string }[];
      pending_joins: { user_id: string }[];
    };
    assert.equal(group.epoch, 1);
    assert.equal(group.members.some((m) => m.user_id === eve.userId), false);
    assert.equal(group.pending_joins.some((p) => p.user_id === eve.userId), true);

    const fan = await json(
      "POST",
      `/v1/groups/${groupId}/fanout`,
      {
        kind: "message",
        ciphertext: Buffer.from("opaque-group").toString("base64"),
        padding_bucket: 256,
      },
      alice.tok,
    );
    assert.equal(fan.status, 200, JSON.stringify(fan.body));
    const eveBox = await json("GET", "/v1/envelopes?limit=20", undefined, eve.tok);
    const eveEnvs = (eveBox.body.envelopes as Array<{ group_id?: string }>) ?? [];
    assert.equal(eveEnvs.some((e) => e.group_id === groupId), false);
  });

  it("rejects a SQL-promoted signer who was not a prior admin", async () => {
    const aDev = devicePayload("alice-prior");
    const bDev = devicePayload("bob-prior");
    const eDev = devicePayload("eve-prior");

    async function signup(phone: string, username: string, dev: ReturnType<typeof devicePayload>) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
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

    const alice = await signup("+79990000081", "aliceprior", aDev);
    const bob = await signup("+79990000082", "bobprior", bDev);
    const eve = await signup("+79990000083", "eveprior", eDev);
    const groupId = crypto.randomUUID();
    const signed = signMembership(
      {
        groupId,
        epoch: 1,
        members: [
          { userId: alice.userId, role: "admin" },
          { userId: bob.userId, role: "member" },
        ],
      },
      aDev.mat.identity,
    );
    const created = await json(
      "POST",
      "/v1/groups",
      {
        id: groupId,
        member_ids: [bob.userId],
        membership: {
          epoch: 1,
          members: signed.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: alice.userId,
          signer_device_id: alice.deviceId,
          signature: Buffer.from(signed.signature).toString("base64"),
        },
      },
      alice.tok,
    );
    assert.equal(created.status, 200, JSON.stringify(created.body));

    const db = await getDb();
    await db.query("UPDATE group_members SET role = $3 WHERE group_id = $1 AND user_id = $2", [
      groupId,
      bob.userId,
      "admin",
    ]);

    const rogue = signMembership(
      {
        groupId,
        epoch: 2,
        members: [
          { userId: alice.userId, role: "admin" },
          { userId: bob.userId, role: "admin" },
          { userId: eve.userId, role: "member" },
        ],
      },
      bDev.mat.identity,
    );
    const injected = await json(
      "POST",
      `/v1/groups/${groupId}/members`,
      {
        user_id: eve.userId,
        membership: {
          epoch: 2,
          members: rogue.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: bob.userId,
          signer_device_id: bob.deviceId,
          signature: Buffer.from(rogue.signature).toString("base64"),
        },
      },
      bob.tok,
    );
    assert.equal(injected.status, 403, JSON.stringify(injected.body));
    assert.equal((injected.body.error as { message?: string } | undefined)?.message, "Signer is not a prior admin");

    await db.query("UPDATE group_members SET role = $3 WHERE group_id = $1 AND user_id = $2", [
      groupId,
      bob.userId,
      "member",
    ]);

    const legit = signMembership(
      {
        groupId,
        epoch: 2,
        members: [
          { userId: alice.userId, role: "admin" },
          { userId: bob.userId, role: "member" },
          { userId: eve.userId, role: "member" },
        ],
      },
      aDev.mat.identity,
    );
    const added = await json(
      "POST",
      `/v1/groups/${groupId}/members`,
      {
        user_id: eve.userId,
        membership: {
          epoch: 2,
          members: legit.members.map((m) => ({ user_id: m.userId, role: m.role })),
          signer_user_id: alice.userId,
          signer_device_id: alice.deviceId,
          signature: Buffer.from(legit.signature).toString("base64"),
        },
      },
      alice.tok,
    );
    assert.equal(added.status, 200, JSON.stringify(added.body));
    assert.equal(added.body.epoch, 2);
  });

  it("issues call rooms without SDP and rejects blocked callees", async () => {
    async function signup(phone: string, username: string) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
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

    const eveJoin = await json("POST", `/v1/calls/${callId}/join`, {}, eve.tok);
    assert.equal(eveJoin.status, 403);

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
      account_ed25519: b64(generateEd25519().publicKey),
      device: aDev.json,
    });
    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000032" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
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

  it("refuses phone enumeration, drops OPKs on revoke, and wipes an account", async () => {
    async function signup(phone: string, username: string) {
      const account = generateEd25519();
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(account.publicKey),
        device: devicePayload(username).json,
      });
      assert.equal(verified.status, 200, JSON.stringify(verified.body));
      const tok = verified.body.access_token as string;
      await json("PUT", "/v1/me", { username, display_name: username }, tok);
      return {
        tok,
        userId: (verified.body.user as { id: string }).id,
        deviceId: verified.body.device_id as string,
        account,
      };
    }
    const alice = await signup("+79990000041", "alicepriv");
    const bob = await signup("+79990000042", "bobpriv");

    const { attach, detach, resetHub } = await import("./realtime/hub.js");
    const onlineWs = { readyState: 1, send() {}, close() {} } as unknown as import("ws").WebSocket;
    const socket = { deviceId: bob.deviceId, userId: bob.userId, ws: onlineWs, resume: "r" };
    attach(socket);
    const hidden = await json("GET", `/v1/presence/${bob.userId}`, undefined, alice.tok);
    assert.equal(hidden.status, 200);
    assert.equal(hidden.body.state, "offline");
    assert.equal(hidden.body.last_seen_day, null);
    await json("POST", "/v1/contacts", { user_id: bob.userId }, alice.tok);
    const visible = await json("GET", `/v1/presence/${bob.userId}`, undefined, alice.tok);
    assert.equal(visible.body.state, "online");
    detach(socket);
    resetHub();

    const phoneLookup = await json(
      "POST",
      "/v1/users/search",
      { phone_e164: "+79990000042" },
      alice.tok,
    );
    assert.equal(phoneLookup.status, 403);

    const depth = await json("GET", "/v1/me/prekey-depth", undefined, bob.tok);
    assert.ok((depth.body.remaining as number) >= 1);

    const chBob = await json("POST", "/v1/auth/challenge", {});
    const proofBob = encodeAuthProof(String(chBob.body.challenge_id), String(chBob.body.nonce));
    const sigBob = sign(bob.account.privateKey, proofBob);
    const bob2 = await json("POST", "/v1/auth/register-key", {
      challenge_id: chBob.body.challenge_id,
      account_ed25519: b64(bob.account.publicKey),
      signature: b64(sigBob),
      device: devicePayload("bob-tablet").json,
    });
    assert.equal(bob2.status, 200, JSON.stringify(bob2.body));
    const bob2Id = bob2.body.device_id as string;
    const bob2Tok = bob2.body.access_token as string;
    const draft = await json(
      "PUT",
      `/v1/drafts/${bob.userId}`,
      { ciphertext: Buffer.from("opaque-draft").toString("base64") },
      bob2Tok,
    );
    assert.equal(draft.status, 200, JSON.stringify(draft.body));
    const listed = await json("GET", "/v1/devices", undefined, bob.tok);
    assert.ok(((listed.body.devices as unknown[]) ?? []).length >= 2);
    assert.equal(typeof listed.body.roster_hash, "string");
    assert.ok(String(listed.body.roster_hash).length === 64);

    const depthBeforePeek = await json("GET", "/v1/me/prekey-depth", undefined, bob.tok);
    const peek = await json("GET", `/v1/keys/${bob.userId}/${bob.deviceId}?consume=0`, undefined, alice.tok);
    assert.equal(peek.status, 200);
    assert.equal((peek.body.bundle as { one_time_prekey: unknown }).one_time_prekey, null);
    const depthAfterPeek = await json("GET", "/v1/me/prekey-depth", undefined, bob.tok);
    assert.equal(depthAfterPeek.body.remaining, depthBeforePeek.body.remaining);

    const consumed = await json("GET", `/v1/keys/${bob.userId}/${bob.deviceId}`, undefined, alice.tok);
    assert.equal(consumed.status, 200, JSON.stringify(consumed.body));
    const usedOpk = (consumed.body.bundle as { one_time_prekey: { id: number } | null }).one_time_prekey;
    assert.ok(usedOpk);
    const db = await getDb();
    const tomb = await db.query<{ n: string }>(
      "SELECT octet_length(public_key)::text AS n FROM one_time_prekeys WHERE device_id = $1 AND key_id = $2",
      [bob.deviceId, usedOpk.id],
    );
    assert.equal(Number(tomb.rows[0]?.n ?? -1), 0);

    const shortKey = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000043" });
    const rejected = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: shortKey.body.challenge_id,
      otp: shortKey.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: {
        ...devicePayload("too-short").json,
        identity_key_x25519: Buffer.from([1, 2, 3]).toString("base64"),
      },
    });
    assert.equal(rejected.status, 400);

    const revoked = await json("DELETE", `/v1/devices/${bob2Id}`, {}, bob.tok);
    assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
    const gone = await json("GET", `/v1/keys/${bob.userId}/${bob2Id}`, undefined, alice.tok);
    assert.equal(gone.status, 404);
    const wiped = await db.query<{ n: string }>(
      "SELECT octet_length(identity_x25519)::text AS n FROM devices WHERE id = $1",
      [bob2Id],
    );
    assert.equal(Number(wiped.rows[0]?.n ?? -1), 0);
    const goneDrafts = await db.query<{ thread_id: string }>(
      "SELECT thread_id FROM drafts WHERE device_id = $1",
      [bob2Id],
    );
    assert.equal(goneDrafts.rows.length, 0);
    const sess = await db.query<{ refresh_hash: string }>(
      "SELECT refresh_hash FROM sessions WHERE device_id = $1",
      [bob2Id],
    );
    assert.ok(sess.rows.length >= 1);
    assert.ok(sess.rows.every((r) => r.refresh_hash.startsWith("revoked:")));

    const report = await json(
      "POST",
      "/v1/reports",
      { user_id: bob.userId, reason: "spam" },
      alice.tok,
    );
    assert.equal(report.status, 200);
    const badReport = await json(
      "POST",
      "/v1/reports",
      { user_id: bob.userId, reason: "секретное сообщение которое нельзя хранить" },
      alice.tok,
    );
    assert.equal(badReport.status, 400);

    const lock = await json(
      "POST",
      "/v1/auth/registration-lock",
      { pin: "lock-pin-ok" },
      alice.tok,
    );
    assert.equal(lock.status, 200, JSON.stringify(lock.body));

    const deleted = await json("POST", "/v1/me/delete", {}, alice.tok);
    assert.equal(deleted.status, 200);
    const aliceKeys = await db.query<{ n: string }>(
      "SELECT octet_length(identity_x25519)::text AS n FROM devices WHERE user_id = $1",
      [alice.userId],
    );
    assert.ok(aliceKeys.rows.length >= 1);
    assert.ok(aliceKeys.rows.every((r) => Number(r.n) === 0));
    const me = await json("GET", "/v1/me", undefined, alice.tok);
    assert.equal(me.status, 401);
    const search = await json("POST", "/v1/users/search", { username: "alicepriv" }, bob.tok);
    assert.equal((search.body.users as unknown[]).length, 0);
  });

  it("caps username changes and does not wake for typing or an online device", async () => {
    const { recentWakes, resetWakes } = await import("./modules/notifications.js");
    const { attach, detach, resetHub } = await import("./realtime/hub.js");
    resetWakes();
    resetHub();

    const aDev = devicePayload("alice-wake");
    const bDev = devicePayload("bob-wake");
    const otpA = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000051" });
    const alice = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpA.body.challenge_id,
      otp: otpA.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: aDev.json,
    });
    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000052" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: bDev.json,
    });
    const aliceTok = alice.body.access_token as string;
    const bobTok = bob.body.access_token as string;
    const bobUser = (bob.body.user as { id: string }).id;
    const bobDevice = bob.body.device_id as string;

    const u1 = await json("PUT", "/v1/me", { username: "wakea1" }, aliceTok);
    assert.equal(u1.status, 200, JSON.stringify(u1.body));
    assert.equal((await json("PUT", "/v1/me", { username: "wakea1" }, aliceTok)).status, 200);
    assert.equal((await json("PUT", "/v1/me", { username: "wakea2" }, aliceTok)).status, 200);
    assert.equal((await json("PUT", "/v1/me", { username: "wakea3" }, aliceTok)).status, 200);
    const limited = await json("PUT", "/v1/me", { username: "wakea4" }, aliceTok);
    assert.equal(limited.status, 429);

    await json("PUT", "/v1/devices/push-token", { token: "fcm-token-wake-device", platform: "web" }, bobTok);
    const opaque = {
      recipient_user_id: bobUser,
      recipient_device_id: bobDevice,
      kind: "typing",
      ciphertext: Buffer.from("opaque-typing").toString("base64"),
      padding_bucket: 256,
    };
    const typed = await json("POST", "/v1/envelopes", { envelopes: [opaque] }, aliceTok);
    assert.equal(typed.status, 200, JSON.stringify(typed.body));
    assert.equal(recentWakes().length, 0);

    const onlineWs = { readyState: 1, send() {} } as unknown as import("ws").WebSocket;
    const socket = { deviceId: bobDevice, userId: bobUser, ws: onlineWs, resume: "r" };
    attach(socket);
    const msgOnline = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            ...opaque,
            kind: "message",
            ciphertext: Buffer.from("opaque-msg-online").toString("base64"),
          },
        ],
      },
      aliceTok,
    );
    assert.equal(msgOnline.status, 200, JSON.stringify(msgOnline.body));
    assert.equal(recentWakes().length, 0);
    await detach(socket);
    resetHub();

    const msgOffline = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            ...opaque,
            kind: "message",
            ciphertext: Buffer.from("opaque-msg-offline").toString("base64"),
          },
        ],
      },
      aliceTok,
    );
    assert.equal(msgOffline.status, 200, JSON.stringify(msgOffline.body));
    assert.ok(recentWakes().length >= 1);
    assert.equal(recentWakes()[recentWakes().length - 1]!.payload.t, "msg");
  });

  it("rotates refresh, kills the family on reuse, and requires registration lock", async () => {
    const account = generateEd25519();
    const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000061" });
    const first = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp.body.challenge_id,
      otp: otp.body.dev_otp,
      account_ed25519: b64(account.publicKey),
      device: devicePayload("lock-phone").json,
    });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const access = first.body.access_token as string;
    const refresh = first.body.refresh_token as string;

    const rotated = await json("POST", "/v1/auth/refresh", { refresh_token: refresh });
    assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
    const nextRefresh = rotated.body.refresh_token as string;
    const nextAccess = rotated.body.access_token as string;
    assert.notEqual(nextRefresh, refresh);

    const reused = await json("POST", "/v1/auth/refresh", { refresh_token: refresh });
    assert.equal(reused.status, 401);
    const familyDead = await json("POST", "/v1/auth/refresh", { refresh_token: nextRefresh });
    assert.equal(familyDead.status, 401);
    const me = await json("GET", "/v1/me", undefined, nextAccess);
    assert.equal(me.status, 200);

    const lock = await json("POST", "/v1/auth/registration-lock", { pin: "lock-pin-ok" }, access);
    assert.equal(lock.status, 200, JSON.stringify(lock.body));

    const chMissing = await json("POST", "/v1/auth/challenge", {});
    const proofMissing = encodeAuthProof(String(chMissing.body.challenge_id), String(chMissing.body.nonce));
    const sigMissing = sign(account.privateKey, proofMissing);
    const missing = await json("POST", "/v1/auth/register-key", {
      challenge_id: chMissing.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sigMissing),
      device: devicePayload("lock-tablet").json,
    });
    assert.equal(missing.status, 403);

    const chOk = await json("POST", "/v1/auth/challenge", {});
    const proofOk = encodeAuthProof(String(chOk.body.challenge_id), String(chOk.body.nonce));
    const sigOk = sign(account.privateKey, proofOk);
    const ok = await json("POST", "/v1/auth/register-key", {
      challenge_id: chOk.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sigOk),
      registration_lock: "lock-pin-ok",
      device: devicePayload("lock-tablet").json,
    });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
  });

  it("registers by Ed25519 possession and finds the public address", async () => {
    const account = generateEd25519();
    const dev = devicePayload("key-web");
    const ch = await json("POST", "/v1/auth/challenge", {});
    assert.equal(ch.status, 200, JSON.stringify(ch.body));
    const proof = encodeAuthProof(String(ch.body.challenge_id), String(ch.body.nonce));
    const sig = sign(account.privateKey, proof);
    const missing = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch.body.challenge_id,
      signature: b64(sig),
      device: dev.json,
    });
    assert.equal(missing.status, 400);
    const reg = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sig),
      device: dev.json,
    });
    assert.equal(reg.status, 200, JSON.stringify(reg.body));
    const tok = reg.body.access_token as string;
    const address = encodeUserUri(account.publicKey);
    assert.notEqual(address, encodeUserUri(dev.mat.identity.ed25519Public));
    const me = await json("GET", "/v1/me", undefined, tok);
    assert.equal(me.status, 200);
    assert.equal((me.body.user as { address: string }).address, address);

    const found = await json("POST", "/v1/users/search", { address }, tok);
    assert.equal(found.status, 200, JSON.stringify(found.body));
    assert.equal(((found.body.users as { id: string }[])[0]).id, (reg.body.user as { id: string }).id);

    const badAddr = await json("POST", "/v1/users/search", { address: "ollo:user:v1:nope" }, tok);
    assert.equal(badAddr.status, 400);

    const other = generateEd25519();
    const ch2 = await json("POST", "/v1/auth/challenge", {});
    const proof2 = encodeAuthProof(String(ch2.body.challenge_id), String(ch2.body.nonce));
    const wrong = sign(other.privateKey, proof2);
    const forged = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch2.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(wrong),
      device: devicePayload("other-key").json,
    });
    assert.equal(forged.status, 401);

    const deviceSig = sign(dev.mat.identity.ed25519Private, proof2);
    const deviceAsAccount = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch2.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(deviceSig),
      device: devicePayload("device-as-account").json,
    });
    assert.equal(deviceAsAccount.status, 401);

    const reuse = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sig),
      device: devicePayload("reuse").json,
    });
    assert.equal(reuse.status, 401);

    const phoneLookup = await json("POST", "/v1/users/search", { phone_e164: "+79990000999" }, tok);
    assert.equal(phoneLookup.status, 403);
  });

  it("restores the same account from the account key onto a new device identity", async () => {
    const account = generateEd25519();
    const firstDev = devicePayload("restore-web");
    const ch = await json("POST", "/v1/auth/challenge", {});
    const proof = encodeAuthProof(String(ch.body.challenge_id), String(ch.body.nonce));
    const sig = sign(account.privateKey, proof);
    const first = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sig),
      device: firstDev.json,
    });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const userId = (first.body.user as { id: string }).id;

    const secondDev = devicePayload("restore-web-2");
    assert.notDeepEqual(secondDev.mat.identity.ed25519Public, firstDev.mat.identity.ed25519Public);
    const ch2 = await json("POST", "/v1/auth/challenge", {});
    const proof2 = encodeAuthProof(String(ch2.body.challenge_id), String(ch2.body.nonce));
    const sig2 = sign(account.privateKey, proof2);
    const again = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch2.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sig2),
      device: secondDev.json,
    });
    assert.equal(again.status, 200, JSON.stringify(again.body));
    assert.equal((again.body.user as { id: string }).id, userId);
    assert.equal((again.body.user as { is_new: boolean }).is_new, false);
    assert.notEqual(again.body.device_id, first.body.device_id);

    const listed = await json("GET", "/v1/devices", undefined, again.body.access_token as string);
    const devices = listed.body.devices as Array<{ id: string; identity_ed25519: string }>;
    assert.equal(devices.length >= 2, true);
    const eds = devices.map((d) => d.identity_ed25519);
    assert.equal(eds.includes(b64(firstDev.mat.identity.ed25519Public)), true);
    assert.equal(eds.includes(b64(secondDev.mat.identity.ed25519Public)), true);
    assert.equal(eds.includes(b64(account.publicKey)), false);
  });

  it("does not attach the OTP device identity as the account key", async () => {
    const bare = devicePayload("otp-bare");
    const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000101" });
    const first = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp.body.challenge_id,
      otp: otp.body.dev_otp,
      device: bare.json,
    });
    assert.equal(first.status, 400, JSON.stringify(first.body));

    const clone = devicePayload("otp-clone");
    const otpClone = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000102" });
    const rejected = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpClone.body.challenge_id,
      otp: otpClone.body.dev_otp,
      account_ed25519: clone.json.identity_key_ed25519,
      device: clone.json,
    });
    assert.equal(rejected.status, 400);

    const account = generateEd25519();
    const dedicated = devicePayload("otp-dedicated");
    const otpOk = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000103" });
    const ok = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpOk.body.challenge_id,
      otp: otpOk.body.dev_otp,
      account_ed25519: b64(account.publicKey),
      device: dedicated.json,
    });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const addressed = await json("GET", "/v1/me", undefined, ok.body.access_token as string);
    assert.equal((addressed.body.user as { address: string }).address, encodeUserUri(account.publicKey));
    assert.notEqual((addressed.body.user as { address: string }).address, encodeUserUri(dedicated.mat.identity.ed25519Public));

    const sms = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000103" });
    const viaOtp = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: sms.body.challenge_id,
      otp: sms.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: devicePayload("otp-sms-attach").json,
    });
    assert.equal(viaOtp.status, 400, JSON.stringify(viaOtp.body));
    const still = await json("GET", "/v1/devices", undefined, ok.body.access_token as string);
    assert.equal(((still.body.devices as unknown[]) ?? []).length, 1);

    const ch = await json("POST", "/v1/auth/challenge", {});
    const proof = encodeAuthProof(String(ch.body.challenge_id), String(ch.body.nonce));
    const sig = sign(account.privateKey, proof);
    const linked = await json("POST", "/v1/auth/register-key", {
      challenge_id: ch.body.challenge_id,
      account_ed25519: b64(account.publicKey),
      signature: b64(sig),
      device: devicePayload("otp-then-key").json,
    });
    assert.equal(linked.status, 200, JSON.stringify(linked.body));
    assert.equal((linked.body.user as { id: string }).id, (ok.body.user as { id: string }).id);
    const two = await json("GET", "/v1/devices", undefined, linked.body.access_token as string);
    assert.equal(((two.body.devices as unknown[]) ?? []).length, 2);
  });

  it("echoes opaque libsignal XEdDSA and does not noble-verify it", async () => {
    const account = generateEd25519();
    const dev = devicePayload("xeddsa-phone");
    const xeddsa = Buffer.alloc(64, 7);
    dev.json.signed_prekey = {
      ...dev.json.signed_prekey,
      xeddsa: xeddsa.toString("base64"),
    };
    const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000201" });
    const reg = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp.body.challenge_id,
      otp: otp.body.dev_otp,
      account_ed25519: b64(account.publicKey),
      device: dev.json,
    });
    assert.equal(reg.status, 200, JSON.stringify(reg.body));
    const tok = reg.body.access_token as string;
    const userId = (reg.body.user as { id: string }).id;
    const deviceId = reg.body.device_id as string;
    const keys = await json("GET", `/v1/keys/${userId}/${deviceId}?consume=0`, undefined, tok);
    assert.equal(keys.status, 200, JSON.stringify(keys.body));
    const bundle = keys.body.bundle as { signed_prekey: { signature: string; xeddsa?: string } };
    assert.equal(bundle.signed_prekey.xeddsa, xeddsa.toString("base64"));
    assert.notEqual(bundle.signed_prekey.xeddsa, bundle.signed_prekey.signature);

    const rotated = Buffer.alloc(64, 9);
    const put = await json(
      "PUT",
      "/v1/keys/signed-prekey",
      {
        id: 2,
        public: dev.json.signed_prekey.public,
        signature: dev.json.signed_prekey.signature,
        xeddsa: rotated.toString("base64"),
      },
      tok,
    );
    assert.equal(put.status, 200, JSON.stringify(put.body));
    const after = await json("GET", `/v1/keys/${userId}/${deviceId}?consume=0`, undefined, tok);
    const next = (after.body.bundle as { signed_prekey: { xeddsa?: string } }).signed_prekey;
    assert.equal(next.xeddsa, rotated.toString("base64"));

    const listed = await json("GET", `/v1/keys/${userId}/devices`, undefined, tok);
    const row = (listed.body.devices as Array<{ signed_prekey: { xeddsa?: string } }>)[0];
    assert.equal(row?.signed_prekey.xeddsa, rotated.toString("base64"));

    const web = devicePayload("no-xeddsa");
    const otpWeb = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000202" });
    const webReg = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpWeb.body.challenge_id,
      otp: otpWeb.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: web.json,
    });
    assert.equal(webReg.status, 200, JSON.stringify(webReg.body));
    const webKeys = await json(
      "GET",
      `/v1/keys/${(webReg.body.user as { id: string }).id}/${webReg.body.device_id as string}?consume=0`,
      undefined,
      webReg.body.access_token as string,
    );
    const webSpk = (webKeys.body.bundle as { signed_prekey: { xeddsa?: string } }).signed_prekey;
    assert.equal(webSpk.xeddsa, undefined);

    const forged = await json(
      "PUT",
      "/v1/keys/signed-prekey",
      {
        id: 3,
        public: web.json.signed_prekey.public,
        signature: Buffer.alloc(64, 1).toString("base64"),
      },
      webReg.body.access_token as string,
    );
    assert.equal(forged.status, 400);
  });

  it("rate-limits auth challenges per client address", async () => {
    const { AUTH_CHALLENGE_PER_IP } = await import("./modules/auth.js");
    const ip = "203.0.113.77";
    let last = 200;
    for (let i = 0; i < AUTH_CHALLENGE_PER_IP + 1; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/v1/auth/challenge",
        payload: {},
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
      });
      last = res.statusCode;
    }
    assert.equal(last, 429);
    const other = await app.inject({
      method: "POST",
      url: "/v1/auth/challenge",
      payload: {},
      headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.78" },
    });
    assert.equal(other.statusCode, 200);
  });

  it("refuses attachment grants from anyone but the uploader", async () => {
    async function signup(phone: string, username: string) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
        device: devicePayload(username).json,
      });
      assert.equal(verified.status, 200, JSON.stringify(verified.body));
      const tok = verified.body.access_token as string;
      await json("PUT", "/v1/me", { username, display_name: username }, tok);
      return {
        tok,
        userId: (verified.body.user as { id: string }).id,
      };
    }
    const alice = await signup("+79990000301", "aliceatt");
    const bob = await signup("+79990000302", "bobatt");
    const created = await json("POST", "/v1/attachments", { size: 4 }, alice.tok);
    assert.equal(created.status, 200, JSON.stringify(created.body));
    const id = created.body.object_id as string;
    const put = await app.inject({
      method: "PUT",
      url: `/v1/attachments/${id}/data`,
      payload: Buffer.from("abcd"),
      headers: {
        authorization: `Bearer ${alice.tok}`,
        "content-type": "application/octet-stream",
      },
    });
    assert.equal(put.statusCode, 200, put.body);
    const stolen = await json(
      "POST",
      `/v1/attachments/${id}/grants`,
      { recipient_user_id: bob.userId },
      bob.tok,
    );
    assert.equal(stolen.status, 403);
    const granted = await json(
      "POST",
      `/v1/attachments/${id}/grants`,
      { recipient_user_id: bob.userId },
      alice.tok,
    );
    assert.equal(granted.status, 200, JSON.stringify(granted.body));
    const token = granted.body.grant as string;
    const peek = await json("GET", `/v1/attachments/${id}?grant=${token}`, undefined, bob.tok);
    assert.equal(peek.status, 200, JSON.stringify(peek.body));
    assert.equal(Object.hasOwn(peek.body, "grant"), false);
    const noGrant = await json("GET", `/v1/attachments/${id}`, undefined, bob.tok);
    assert.equal(noGrant.status, 403);
    const viaHeader = await app.inject({
      method: "GET",
      url: `/v1/attachments/${id}/data`,
      headers: {
        authorization: `Bearer ${bob.tok}`,
        "x-attachment-grant": token,
      },
    });
    assert.equal(viaHeader.statusCode, 200, viaHeader.body);
    assert.equal(Buffer.from(viaHeader.rawPayload).toString("utf8"), "abcd");
    const { createHash } = await import("node:crypto");
    const digest = createHash("sha256").update("abcd").digest("hex");
    const lied = await json(
      "POST",
      `/v1/attachments/${id}/complete`,
      { digest: "00".repeat(32), size: 4 },
      alice.tok,
    );
    assert.equal(lied.status, 400);
    const okDigest = await json(
      "POST",
      `/v1/attachments/${id}/complete`,
      { digest, size: 4 },
      alice.tok,
    );
    assert.equal(okDigest.status, 200, JSON.stringify(okDigest.body));
  });

  it("pages envelopes by created_at then id and binds LIMIT", async () => {
    const aDev = devicePayload("alice-cur");
    const bDev = devicePayload("bob-cur");
    const otpA = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000311" });
    const alice = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpA.body.challenge_id,
      otp: otpA.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: aDev.json,
    });
    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000312" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
      account_ed25519: b64(generateEd25519().publicKey),
      device: bDev.json,
    });
    assert.equal(alice.status, 200, JSON.stringify(alice.body));
    assert.equal(bob.status, 200, JSON.stringify(bob.body));
    const aliceTok = alice.body.access_token as string;
    const bobTok = bob.body.access_token as string;
    const bobUser = (bob.body.user as { id: string }).id;
    const bobDevice = bob.body.device_id as string;
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const sent = await json(
        "POST",
        "/v1/envelopes",
        {
          envelopes: [
            {
              recipient_user_id: bobUser,
              recipient_device_id: bobDevice,
              kind: "control",
              ciphertext: Buffer.from(`opaque-page-${i}`).toString("base64"),
              padding_bucket: 256,
            },
          ],
        },
        aliceTok,
      );
      assert.equal(sent.status, 200, JSON.stringify(sent.body));
      ids.push(((sent.body.accepted as Array<{ id: string }>)[0]!).id);
    }
    const first = await json("GET", "/v1/envelopes?limit=1", undefined, bobTok);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    const page1 = first.body.envelopes as Array<{ id: string }>;
    assert.equal(page1.length, 1);
    assert.equal(first.body.next_cursor, page1[0]!.id);
    const second = await json(
      "GET",
      `/v1/envelopes?limit=1&cursor=${page1[0]!.id}`,
      undefined,
      bobTok,
    );
    assert.equal(second.status, 200, JSON.stringify(second.body));
    const page2 = second.body.envelopes as Array<{ id: string }>;
    assert.equal(page2.length, 1);
    assert.notEqual(page2[0]!.id, page1[0]!.id);
    const rest = await json(
      "GET",
      `/v1/envelopes?limit=10&cursor=${page2[0]!.id}`,
      undefined,
      bobTok,
    );
    const page3 = rest.body.envelopes as Array<{ id: string }>;
    assert.equal(page3.length, 1);
    assert.equal(rest.body.next_cursor, null);
    const seen = new Set([page1[0]!.id, page2[0]!.id, page3[0]!.id]);
    assert.equal(seen.size, 3);
    for (const id of ids) assert.equal(seen.has(id), true);
    const bad = await json("GET", "/v1/envelopes?cursor=not-a-uuid", undefined, bobTok);
    assert.equal(bad.status, 400);
  });

  it("replays Idempotency-Key and rejects a stolen envelope id", async () => {
    const { listMailbox } = await import("./modules/messaging.js");
    async function signup(phone: string, username: string) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
        account_ed25519: b64(generateEd25519().publicKey),
        device: devicePayload(username).json,
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
    const alice = await signup("+79990000401", "aliceidem");
    const bob = await signup("+79990000402", "bobidem");
    const eve = await signup("+79990000403", "eveidem");

    const envId = crypto.randomUUID();
    const idem = crypto.randomUUID();
    const payload = {
      envelopes: [
        {
          id: envId,
          recipient_user_id: bob.userId,
          recipient_device_id: bob.deviceId,
          kind: "control",
          ciphertext: Buffer.from("opaque-idem").toString("base64"),
          padding_bucket: 256,
        },
      ],
    };
    const first = await app.inject({
      method: "POST",
      url: "/v1/envelopes",
      payload,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.tok}`,
        "idempotency-key": idem,
      },
    });
    assert.equal(first.statusCode, 200, first.body);
    const accepted = (first.json() as { accepted: Array<{ id: string }> }).accepted;
    assert.equal(accepted[0]?.id, envId);

    const replay = await app.inject({
      method: "POST",
      url: "/v1/envelopes",
      payload,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.tok}`,
        "idempotency-key": idem,
      },
    });
    assert.equal(replay.statusCode, 200, replay.body);
    assert.equal(replay.headers["idempotent-replayed"], "1");
    assert.deepEqual(replay.json(), first.json());

    const retrySameId = await json("POST", "/v1/envelopes", payload, alice.tok);
    assert.equal(retrySameId.status, 200, JSON.stringify(retrySameId.body));
    assert.equal(((retrySameId.body.accepted as Array<{ id: string }>)[0]).id, envId);

    const stolen = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            id: envId,
            recipient_user_id: bob.userId,
            recipient_device_id: bob.deviceId,
            kind: "control",
            ciphertext: Buffer.from("eve-occupancy").toString("base64"),
            padding_bucket: 256,
          },
        ],
      },
      eve.tok,
    );
    assert.equal(stolen.status, 409);

    const box = await json("GET", "/v1/envelopes?limit=20", undefined, bob.tok);
    const envs = box.body.envelopes as Array<{ id: string; ciphertext: string }>;
    const hits = envs.filter((e) => e.id === envId);
    assert.equal(hits.length, 1);
    assert.equal(Buffer.from(hits[0]!.ciphertext, "base64").toString("utf8"), "opaque-idem");

    const laterId = crypto.randomUUID();
    const later = await json(
      "POST",
      "/v1/envelopes",
      {
        envelopes: [
          {
            id: laterId,
            recipient_user_id: bob.userId,
            recipient_device_id: bob.deviceId,
            kind: "control",
            ciphertext: Buffer.from("opaque-after").toString("base64"),
            padding_bucket: 256,
          },
        ],
      },
      alice.tok,
    );
    assert.equal(later.status, 200, JSON.stringify(later.body));
    const drained = await listMailbox(await getDb(), bob.deviceId, envId, 200);
    assert.equal(drained.envelopes.some((e) => e.id === envId), false);
    assert.equal(drained.envelopes.some((e) => e.id === laterId), true);

    const badKey = await app.inject({
      method: "POST",
      url: "/v1/envelopes",
      payload,
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${alice.tok}`,
        "idempotency-key": "not-a-uuid",
      },
    });
    assert.equal(badKey.statusCode, 400);

    const metrics = await app.inject({ method: "GET", url: "/metrics" });
    assert.equal(metrics.statusCode, 200);
  });
});
