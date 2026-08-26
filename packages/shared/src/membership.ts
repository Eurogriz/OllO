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
}): MembershipDecision {
  if (!args.signatureValid) return "drop";
  if (args.signerRole !== "admin") return "drop";
  if (args.incomingEpoch < 1 || !args.incomingHash) return "drop";
  if (args.rejectedHashes?.includes(args.incomingHash)) return "rejected";
  if (args.localMembers && args.signerUserId) {
    const prior = args.localMembers.find((m) => m.userId === args.signerUserId);
    if (!prior || prior.role !== "admin") return "drop";
  }
  if (!args.local) return "accept";
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
