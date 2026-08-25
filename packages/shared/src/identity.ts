/**
 * Remote identity bookkeeping. A changed key is a hard warning: do not
 * overwrite the stored fingerprint until the user re-verifies.
 */
export type IdentityDecision = "new" | "unchanged" | "changed";

export function noteRemoteIdentity(previousFp: string | undefined, nextFp: string): IdentityDecision {
  if (!previousFp) return "new";
  return previousFp === nextFp ? "unchanged" : "changed";
}

export function sessionAddress(userId: string, deviceId: string): string {
  return `${userId}:${deviceId}`;
}
