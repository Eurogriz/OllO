import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { beginSession, createLocalDevice, encryptFirstMessage, signMembership } from "@ollo/crypto";
import { encodeSealed, paddingBucket } from "@ollo/protocol";

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
    const otpGone = await (await getDb()).query<{ id: string }>(
      "SELECT id FROM otp_challenges WHERE id = $1",
      [otpA.body.challenge_id],
    );
    assert.equal(otpGone.rows.length, 0);

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

  it("refuses phone enumeration, drops OPKs on revoke, and wipes an account", async () => {
    async function signup(phone: string, username: string) {
      const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: phone });
      const verified = await json("POST", "/v1/auth/verify-otp", {
        challenge_id: otp.body.challenge_id,
        otp: otp.body.dev_otp,
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

    const second = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000042" });
    const bob2 = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: second.body.challenge_id,
      otp: second.body.dev_otp,
      device: devicePayload("bob-tablet").json,
    });
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
      device: aDev.json,
    });
    const otpB = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000052" });
    const bob = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otpB.body.challenge_id,
      otp: otpB.body.dev_otp,
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
    detach(socket);
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
    const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000061" });
    const first = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp.body.challenge_id,
      otp: otp.body.dev_otp,
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

    // OTP window is 3/min per phone. Signup used one slot; keep two for lock.
    const otp2 = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000061" });
    const missing = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp2.body.challenge_id,
      otp: otp2.body.dev_otp,
      device: devicePayload("lock-tablet").json,
    });
    assert.equal(missing.status, 403);

    const otp3 = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990000061" });
    const ok = await json("POST", "/v1/auth/verify-otp", {
      challenge_id: otp3.body.challenge_id,
      otp: otp3.body.dev_otp,
      registration_lock: "lock-pin-ok",
      device: devicePayload("lock-tablet").json,
    });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
  });
});
