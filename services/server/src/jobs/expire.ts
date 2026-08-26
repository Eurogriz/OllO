import type { Db } from "../db/index.js";
import { log } from "../observability/logger.js";

export async function expireStale(
  db: Db,
): Promise<{
  envelopes: number;
  attachments: number;
  prekeys: number;
  revoked_keys: number;
  otp: number;
  drafts: number;
}> {
  const envelopes = await db.query<{ id: string }>(
    `DELETE FROM envelopes
     WHERE (expires_at IS NOT NULL AND expires_at < now())
        OR acked_at IS NOT NULL
     RETURNING id`,
  );
  const attachments = await db.query<{ id: string }>(
    "DELETE FROM attachments WHERE expires_at < now() AND completed_at IS NOT NULL RETURNING id",
  );
  const otp = await db.query<{ id: string }>(
    `DELETE FROM otp_challenges
     WHERE expires_at < now() OR consumed_at IS NOT NULL
     RETURNING id`,
  );
  await db.query(
    `DELETE FROM auth_challenges
     WHERE expires_at < now() OR consumed_at IS NOT NULL`,
  );
  const drafts = await db.query<{ thread_id: string }>(
    `DELETE FROM drafts
     WHERE device_id IN (SELECT id FROM devices WHERE revoked_at IS NOT NULL)
     RETURNING thread_id`,
  );
  const prekeys = await db.query<{ key_id: number }>(
    `DELETE FROM one_time_prekeys
     WHERE consumed_at IS NOT NULL AND consumed_at < now() - interval '14 days'
     RETURNING key_id`,
  );
  const empty = Buffer.alloc(0);
  const revoked = await db.query<{ id: string }>(
    `UPDATE devices SET
       identity_x25519 = $1,
       identity_ed25519 = $1,
       signed_prekey_public = $1,
       signed_prekey_sig = $1,
       signed_prekey_xeddsa = $1,
       push_token_enc = NULL
     WHERE revoked_at IS NOT NULL
       AND (
         octet_length(identity_x25519) > 0
         OR octet_length(identity_ed25519) > 0
         OR octet_length(signed_prekey_public) > 0
         OR octet_length(signed_prekey_sig) > 0
         OR (signed_prekey_xeddsa IS NOT NULL AND octet_length(signed_prekey_xeddsa) > 0)
         OR push_token_enc IS NOT NULL
       )
     RETURNING id`,
    [empty],
  );
  const result = {
    envelopes: envelopes.rows.length,
    attachments: attachments.rows.length,
    prekeys: prekeys.rows.length,
    revoked_keys: revoked.rows.length,
    otp: otp.rows.length,
    drafts: drafts.rows.length,
  };
  if (result.envelopes || result.attachments || result.prekeys || result.revoked_keys || result.otp || result.drafts) {
    log.info("expired stale rows", result);
  }
  return result;
}

export function startExpiryLoop(db: Db, everyMs = 60_000): NodeJS.Timeout {
  return setInterval(() => {
    void expireStale(db).catch((err: Error) => {
      log.error("expire job failed", { err: err.message });
    });
  }, everyMs);
}
