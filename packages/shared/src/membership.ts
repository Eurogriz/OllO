/**
 * Membership apply policy. Signature check lives in @ollo/crypto;
 * this only decides whether a verified roster replaces local state
 * and which user ids may receive sender keys.
 */
export type MembershipDecision = "accept" | "confirm" | "unchanged" | "stale" | "drop" | "rejected";

export type MembershipSignerNotice = "self" | "own-other-device" | "other-admin";

export interface LocalMembership {
  epoch: number;
  hash: string;
}

export const MAX_REJECTED_MEMBERSHIP_HASHES = 32;

export function planMembershipDelta(
  local: { userId: string; role: string }[],
  incoming: { userId: string; role: string }[],
): { added: string[]; removed: string[]; roleChanged: string[] } {
  const loc = new Map(local.filter((m) => m.userId).map((m) => [m.userId, m.role]));
  const inc = new Map(incoming.filter((m) => m.userId).map((m) => [m.userId, m.role]));
  return {
    added: [...inc.keys()].filter((id) => !loc.has(id)),
    removed: [...loc.keys()].filter((id) => !inc.has(id)),
    roleChanged: [...inc.keys()].filter((id) => loc.has(id) && loc.get(id) !== inc.get(id)),
  };
}

/** Bounded FIFO of refused roster hashes. Same hash is not stored twice. */
export function planRejectedHashes(existing: string[], nextHash: string, max = MAX_REJECTED_MEMBERSHIP_HASHES): string[] {
  if (!nextHash) return existing.filter(Boolean).slice(-max);
  const out = existing.filter((h) => h && h !== nextHash);
  out.push(nextHash);
  return out.slice(-max);
}

/**
 * Another of this user's devices signed the roster (stolen-admin residual
 * on honest devices). `self` is this device; `other-admin` is not us.
 */
export function planMembershipSignerNotice(args: {
  localUserId: string;
  localDeviceId: string;
  signerUserId: string;
  signerDeviceId: string;
}): MembershipSignerNotice {
  if (!args.localUserId || !args.localDeviceId || !args.signerUserId || !args.signerDeviceId) {
    return "other-admin";
  }
  if (args.signerUserId !== args.localUserId) return "other-admin";
  return args.signerDeviceId === args.localDeviceId ? "self" : "own-other-device";
}

export function planMembershipApply(args: {
  local?: LocalMembership;
  incomingEpoch: number;
  incomingHash: string;
  signatureValid: boolean;
  signerRole: string;
  signerUserId?: string;
  localMembers?: { userId: string; role: string }[];
  incomingMembers?: { userId: string; role: string }[];
  rejectedHashes?: string[];
  localDeviceId?: string;
  signerDeviceId?: string;
}): MembershipDecision {
  if (!args.signatureValid) return "drop";
  if (args.signerRole !== "admin") return "drop";
  if (args.incomingEpoch < 1 || !args.incomingHash) return "drop";
  if (args.rejectedHashes?.includes(args.incomingHash)) return "rejected";
  if (args.localMembers && args.signerUserId) {
    const prior = args.localMembers.find((m) => m.userId === args.signerUserId);
    if (!prior || prior.role !== "admin") return "drop";
  }
  if (!args.local) {
    if (args.localDeviceId && args.signerDeviceId) {
      return args.localDeviceId === args.signerDeviceId ? "accept" : "confirm";
    }
    return "accept";
  }
  if (args.incomingEpoch < args.local.epoch) return "stale";
  if (args.incomingEpoch === args.local.epoch) {
    return args.incomingHash === args.local.hash ? "unchanged" : "drop";
  }
  if (args.localMembers && args.incomingMembers) {
    const delta = planMembershipDelta(args.localMembers, args.incomingMembers);
    if (delta.added.length || delta.roleChanged.length) return "confirm";
  }
  return "accept";
}

export function planTrustedMembers(
  signedUserIds: string[],
  serverUserIds: string[],
): { trusted: string[]; extra: string[]; missing: string[] } {
  const signed = new Set(signedUserIds.filter(Boolean));
  const server = new Set(serverUserIds.filter(Boolean));
  return {
    trusted: [...signed].filter((id) => server.has(id)),
    extra: [...server].filter((id) => !signed.has(id)),
    missing: [...signed].filter((id) => !server.has(id)),
  };
}

/**
 * Install a sender-key distribution only for locally trusted members.
 * `hold` = in the pending roster, not yet confirmed (new-device TOFU or add).
 */
export function planSenderKeyIngest(args: {
  trustedUserIds: string[];
  pendingUserIds: string[];
  senderUserId: string;
  senderDeviceId?: string;
  droppedDevices?: string[];
}): "accept" | "hold" | "drop" {
  if (!args.senderUserId) return "drop";
  if (
    args.senderDeviceId &&
    args.droppedDevices?.includes(droppedDeviceKey(args.senderUserId, args.senderDeviceId))
  ) {
    return "drop";
  }
  if (args.trustedUserIds.includes(args.senderUserId)) return "accept";
  if (args.pendingUserIds.includes(args.senderUserId)) return "hold";
  return "drop";
}

export function planHeldSenderKeyFlush(
  held: { slot: string; userId: string }[],
  trustedUserIds: string[],
): { install: string[]; discard: string[] } {
  const trusted = new Set(trustedUserIds.filter(Boolean));
  const install: string[] = [];
  const discard: string[] = [];
  for (const h of held) {
    if (!h.slot) continue;
    if (trusted.has(h.userId)) install.push(h.slot);
    else discard.push(h.slot);
  }
  return { install, discard };
}

/** Slot is `groupId:userId:deviceId:epoch`. UUIDs have no extra colons. */
export function parseSenderKeySlot(
  slot: string,
): { groupId: string; userId: string; deviceId: string; epoch: string } | null {
  const parts = slot.split(":");
  if (parts.length !== 4) return null;
  const [groupId, userId, deviceId, epoch] = parts;
  if (!groupId || !userId || !deviceId || !epoch) return null;
  return { groupId, userId, deviceId, epoch };
}

/** Drop remote/held sender-key slots for a user (leave) or a device (revoke). */
export function planSenderKeyPrune(
  slots: string[],
  filter: { userId?: string; deviceId?: string },
): string[] {
  if (!filter.userId && !filter.deviceId) return [];
  return slots.filter((slot) => {
    const p = parseSenderKeySlot(slot);
    if (!p) return false;
    if (filter.userId && p.userId !== filter.userId) return false;
    if (filter.deviceId && p.deviceId !== filter.deviceId) return false;
    return true;
  });
}

export const MAX_DROPPED_DEVICES = 64;

export function droppedDeviceKey(userId: string, deviceId: string): string {
  if (!userId || !deviceId) return "";
  return `${userId}:${deviceId}`;
}

export function planDroppedDevices(
  existing: string[],
  userId: string,
  deviceId: string,
  max = MAX_DROPPED_DEVICES,
): string[] {
  const next = droppedDeviceKey(userId, deviceId);
  if (!next) return existing.filter(Boolean).slice(-max);
  const out = existing.filter((h) => h && h !== next);
  out.push(next);
  return out.slice(-max);
}

/** Fan-out only to the signed ∩ live intersection. Empty signed roster → nobody. */
export function planFanoutRecipients(signedUserIds: string[], serverUserIds: string[]): string[] {
  if (!signedUserIds.some(Boolean)) return [];
  return planTrustedMembers(signedUserIds, serverUserIds).trusted;
}

export function sameMembership(
  a: { userId: string; role: string }[],
  b: { userId: string; role: string }[],
): boolean {
  if (a.length !== b.length) return false;
  const as = [...a].sort((x, y) => (x.userId < y.userId ? -1 : x.userId > y.userId ? 1 : 0));
  const bs = [...b].sort((x, y) => (x.userId < y.userId ? -1 : x.userId > y.userId ? 1 : 0));
  return as.every((m, i) => m.userId === bs[i]!.userId && m.role === bs[i]!.role);
}
