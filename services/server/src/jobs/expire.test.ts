import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

process.env.OLLO_ENV = "development";
process.env.PGLITE_DATA_DIR = mkdtempSync(join(tmpdir(), "ollo-expire-"));
process.env.PHONE_HMAC_PEPPER = "test-phone-pepper";
process.env.SESSION_SIGNING_KEY = "test-session-key";
process.env.OTP_PEPPER = "test-otp-pepper";

const { getDb, closeDb } = await import("../db/index.js");
const { expireStale } = await import("./expire.js");

describe("TTL expiry job", () => {
  const dir = process.env.PGLITE_DATA_DIR!;
  let db: Awaited<ReturnType<typeof getDb>>;

  before(async () => {
    db = await getDb();
  });

  after(async () => {
    await closeDb();
    rmSync(dir, { recursive: true, force: true });
  });

  it("deletes expired envelopes and attachments including grants, keeps live rows", async () => {
    const deadEnv = crypto.randomUUID();
    const liveEnv = crypto.randomUUID();
    const deadAtt = crypto.randomUUID();
    const liveAtt = crypto.randomUUID();
    const uid = crypto.randomUUID();

    await db.query(
      `INSERT INTO envelopes (
         id, sender_user_id, sender_device_id, recipient_user_id, recipient_device_id,
         kind, payload, padding_bucket, expires_at
       ) VALUES
         ($1,$3,$3,$3,$3,'message',$4,256, now() - interval '1 hour'),
         ($2,$3,$3,$3,$3,'message',$4,256, now() + interval '1 day')`,
      [deadEnv, liveEnv, uid, Buffer.from("ciphertext-only")],
    );
    const incompleteAtt = crypto.randomUUID();
    await db.query(
      `INSERT INTO attachments (id, uploader_device_id, object_key, size, expires_at, completed_at)
       VALUES
         ($1,$3,$4,12, now() - interval '1 hour', now()),
         ($2,$3,$5,12, now() + interval '1 day', now()),
         ($6,$3,$7,4, now() - interval '1 hour', NULL)`,
      [deadAtt, liveAtt, uid, `obj-${deadAtt}`, `obj-${liveAtt}`, incompleteAtt, `obj-${incompleteAtt}`],
    );
    await db.query(
      `INSERT INTO attachment_grants (token_hash, attachment_id, recipient_user_id, expires_at)
       VALUES ('dead-grant', $1, $2, now() + interval '1 day')`,
      [deadAtt, uid],
    );

    const did = crypto.randomUUID();
    const key = Buffer.from([1, 2, 3, 4]);
    await db.query(`INSERT INTO users (id, phone_hmac, display_name) VALUES ($1,$2,'')`, [
      uid,
      `hmac-${uid}`,
    ]);
    await db.query(
      `INSERT INTO devices (
         id, user_id, name, platform, registration_id,
         identity_x25519, identity_ed25519,
         signed_prekey_id, signed_prekey_public, signed_prekey_sig
       ) VALUES ($1,$2,'t','web',1,$3,$3,1,$3,$3)`,
      [did, uid, key],
    );
    await db.query(
      `INSERT INTO one_time_prekeys (device_id, key_id, public_key, consumed_at) VALUES
         ($1, 1, $2, now() - interval '15 days'),
         ($1, 2, $2, now()),
         ($1, 3, $2, NULL)`,
      [did, key],
    );

    const revokedDid = crypto.randomUUID();
    await db.query(
      `INSERT INTO devices (
         id, user_id, name, platform, registration_id,
         identity_x25519, identity_ed25519,
         signed_prekey_id, signed_prekey_public, signed_prekey_sig, revoked_at
       ) VALUES ($1,$2,'revoked','web',1,$3,$3,1,$3,$3, now() - interval '1 day')`,
      [revokedDid, uid, key],
    );
    await db.query(
      `INSERT INTO drafts (user_id, device_id, thread_id, ciphertext) VALUES
         ($1, $2, 'dead-draft', $4),
         ($1, $3, 'live-draft', $4)`,
      [uid, revokedDid, did, Buffer.from("opaque-draft")],
    );
    await db.query(
      `INSERT INTO otp_challenges (id, phone_hmac, otp_hash, expires_at) VALUES
         ('ch-dead', 'hmac-otp', 'hash', now() - interval '1 hour'),
         ('ch-live', 'hmac-otp', 'hash', now() + interval '5 minutes')`,
    );
    await db.query(
      `INSERT INTO idempotency (scope, key, status, body, created_at) VALUES
         ('user:x', 'k-old', 200, '{}', now() - interval '25 hours'),
         ('user:x', 'k-pending', -1, '', now() - interval '5 minutes'),
         ('user:x', 'k-live', 200, '{}', now())`,
    );

    const result = await expireStale(db);
    assert.equal(result.envelopes, 1);
    assert.equal(result.attachments, 2);
    assert.equal(result.prekeys, 1);
    assert.equal(result.revoked_keys, 1);
    assert.equal(result.otp, 1);
    assert.equal(result.drafts, 1);
    assert.equal(result.idempotency, 2);

    const envs = await db.query<{ id: string }>("SELECT id FROM envelopes");
    assert.deepEqual(envs.rows.map((r) => r.id), [liveEnv]);
    const atts = await db.query<{ id: string }>("SELECT id FROM attachments");
    assert.deepEqual(atts.rows.map((r) => r.id), [liveAtt]);
    const grants = await db.query<{ token_hash: string }>("SELECT token_hash FROM attachment_grants");
    assert.equal(grants.rows.length, 0);
    const opks = await db.query<{ key_id: number }>(
      "SELECT key_id FROM one_time_prekeys ORDER BY key_id",
    );
    assert.deepEqual(
      opks.rows.map((r) => r.key_id),
      [2, 3],
    );
    const live = await db.query<{ n: string }>(
      "SELECT octet_length(identity_x25519)::text AS n FROM devices WHERE id = $1",
      [did],
    );
    assert.equal(Number(live.rows[0]?.n), 4);
    const wiped = await db.query<{ n: string }>(
      "SELECT octet_length(identity_x25519)::text AS n FROM devices WHERE id = $1",
      [revokedDid],
    );
    assert.equal(Number(wiped.rows[0]?.n), 0);
    const drafts = await db.query<{ thread_id: string }>("SELECT thread_id FROM drafts");
    assert.deepEqual(drafts.rows.map((r) => r.thread_id), ["live-draft"]);
    const otps = await db.query<{ id: string }>("SELECT id FROM otp_challenges");
    assert.deepEqual(otps.rows.map((r) => r.id), ["ch-live"]);
    const keys = await db.query<{ key: string }>("SELECT key FROM idempotency");
    assert.deepEqual(
      keys.rows.map((r) => r.key),
      ["k-live"],
    );
  });
});
