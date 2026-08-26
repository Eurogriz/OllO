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
