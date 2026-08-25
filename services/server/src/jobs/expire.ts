import type { Db } from "../db/index.js";
import { log } from "../observability/logger.js";

export async function expireStale(
  db: Db,
): Promise<{ envelopes: number; attachments: number; prekeys: number }> {
  const envelopes = await db.query<{ id: string }>(
    "DELETE FROM envelopes WHERE expires_at IS NOT NULL AND expires_at < now() RETURNING id",
  );
  const attachments = await db.query<{ id: string }>(
    "DELETE FROM attachments WHERE expires_at < now() AND completed_at IS NOT NULL RETURNING id",
  );
  const prekeys = await db.query<{ key_id: number }>(
    `DELETE FROM one_time_prekeys
     WHERE consumed_at IS NOT NULL AND consumed_at < now() - interval '14 days'
     RETURNING key_id`,
  );
  const result = {
    envelopes: envelopes.rows.length,
    attachments: attachments.rows.length,
    prekeys: prekeys.rows.length,
  };
  if (result.envelopes || result.attachments || result.prekeys) {
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
