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

    const result = await expireStale(db);
    assert.equal(result.envelopes, 1);
    assert.equal(result.attachments, 1);

    const envs = await db.query<{ id: string }>("SELECT id FROM envelopes");
    assert.deepEqual(envs.rows.map((r) => r.id), [liveEnv]);
    const atts = await db.query<{ id: string }>("SELECT id FROM attachments");
    assert.deepEqual(atts.rows.map((r) => r.id), [liveAtt]);
  });
});
