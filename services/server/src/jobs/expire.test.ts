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

  it("deletes expired envelopes and completed attachments, keeps live rows", async () => {
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
    await db.query(
      `INSERT INTO attachments (id, uploader_device_id, object_key, size, expires_at, completed_at)
       VALUES
         ($1,$3,$4,12, now() - interval '1 hour', now()),
         ($2,$3,$5,12, now() + interval '1 day', now())`,
      [deadAtt, liveAtt, uid, `obj-${deadAtt}`, `obj-${liveAtt}`],
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

    const result = await expireStale(db);
    assert.equal(result.envelopes, 1);
    assert.equal(result.attachments, 1);
    assert.equal(result.prekeys, 1);

    const envs = await db.query<{ id: string }>("SELECT id FROM envelopes");
    assert.deepEqual(envs.rows.map((r) => r.id), [liveEnv]);
    const atts = await db.query<{ id: string }>("SELECT id FROM attachments");
    assert.deepEqual(atts.rows.map((r) => r.id), [liveAtt]);
    const opks = await db.query<{ key_id: number }>(
      "SELECT key_id FROM one_time_prekeys ORDER BY key_id",
    );
    assert.deepEqual(
      opks.rows.map((r) => r.key_id),
      [2, 3],
    );
  });
});
