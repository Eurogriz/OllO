/**
 * What a sealed account backup may carry.
 *
 * Identity material is the recovery root. Session tokens, the replay cache,
 * and the outbox must never be written into the blob — a shared or leaked
 * backup must not yield a live session.
 */
export type BackupAccept = "accept" | "drop";

export function planBackupExport(_input: { access: string; refresh: string }): {
  access: "";
  refresh: "";
  replay: { ids: [] };
  outbox: [];
} {
  return { access: "", refresh: "", replay: { ids: [] }, outbox: [] };
}

export function planBackupAccept(input: {
  hasIdentity: boolean;
  access: string;
  refresh: string;
}): BackupAccept {
  if (!input.hasIdentity) return "drop";
  if (input.access || input.refresh) return "drop";
  return "accept";
}
