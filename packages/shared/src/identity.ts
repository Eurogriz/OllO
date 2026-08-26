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

export const X25519_PUBLIC_LEN = 32;
export const ED25519_PUBLIC_LEN = 32;
export const ED25519_SIGNATURE_LEN = 64;

/** Directory material only: exact public length, not empty or all-zero. */
export function planPublicKeyAccept(bytes: Uint8Array, expected: number): "accept" | "drop" {
  if (!Number.isInteger(expected) || expected < 1) return "drop";
  if (bytes.length !== expected) return "drop";
  for (const b of bytes) {
    if (b !== 0) return "accept";
  }
  return "drop";
}

/**
 * Sessions whose device is no longer on that user's live roster.
 * Prefix is `userId:` so `u1` cannot match `u10`.
 */
export function planRosterPrune(
  sessionKeys: string[],
  userId: string,
  liveDeviceIds: Iterable<string>,
): string[] {
  if (!userId) return [];
  const live = new Set(liveDeviceIds);
  const prefix = `${userId}:`;
  return sessionKeys.filter((k) => k.startsWith(prefix) && !live.has(k.slice(prefix.length)));
}

/** Drop the single address of a device that was just revoked. */
export function planDeviceDrop(sessionKeys: string[], userId: string, deviceId: string): string[] {
  if (!userId || !deviceId) return [];
  const target = sessionAddress(userId, deviceId);
  return sessionKeys.filter((k) => k === target);
}

/** Refuse acceptSession / beginSession for a locally dropped device. */
export function planSessionAccept(args: {
  userId: string;
  deviceId: string;
  droppedDevices?: string[];
}): "accept" | "drop" {
  if (!args.userId || !args.deviceId) return "drop";
  if (args.droppedDevices?.includes(sessionAddress(args.userId, args.deviceId))) return "drop";
  return "accept";
}

/**
 * libsignal SessionCipher: a PreKeySignalMessage is always run through
 * SessionBuilder.process, which archives the current SessionRecord and
 * starts a new ratchet. A regular message needs an existing session.
 */
export function planSessionOpen(args: {
  hasSession: boolean;
  hasPrekey: boolean;
}): "use-session" | "accept-prekey" | "drop" {
  if (args.hasPrekey) return "accept-prekey";
  if (args.hasSession) return "use-session";
  return "drop";
}

/** libsignal SessionRecord.ARCHIVED_STATES_MAX_LENGTH */
export const MAX_ARCHIVED_SESSIONS = 40;

/** Archive the live ratchet before a PreKey rebuild. */
export function planSessionArchive(hasCurrent: boolean): "archive" | "skip" {
  return hasCurrent ? "archive" : "skip";
}

/** How many oldest archived states to drop. */
export function planArchiveTrim(count: number, max = MAX_ARCHIVED_SESSIONS): number {
  if (!Number.isInteger(count) || count < 0) return 0;
  if (!Number.isInteger(max) || max < 1) return 0;
  return count > max ? count - max : 0;
}

/**
 * Another of this user's still-live devices announced a revoke.
 * Fail closed without a directory snapshot. Refuse if the target is still live
 * so a stolen sibling cannot drop an honest device.
 */
export function planDeviceDropNotice(args: {
  senderUserId: string;
  senderDeviceId: string;
  targetUserId: string;
  targetDeviceId: string;
  liveDeviceIds?: string[];
}): "apply" | "drop" {
  if (!args.senderUserId || !args.senderDeviceId || !args.targetUserId || !args.targetDeviceId) {
    return "drop";
  }
  if (args.senderUserId !== args.targetUserId) return "drop";
  if (args.senderDeviceId === args.targetDeviceId) return "drop";
  if (!args.liveDeviceIds) return "drop";
  if (args.liveDeviceIds.includes(args.targetDeviceId)) return "drop";
  return "apply";
}
