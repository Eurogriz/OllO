/**
 * Membership apply policy. Signature check lives in @ollo/crypto;
 * this only decides whether a verified roster replaces local state
 * and which user ids may receive sender keys.
 */
export type MembershipDecision = "accept" | "unchanged" | "stale" | "drop";

export interface LocalMembership {
  epoch: number;
  hash: string;
}

export function planMembershipApply(args: {
  local?: LocalMembership;
  incomingEpoch: number;
  incomingHash: string;
  signatureValid: boolean;
  signerRole: string;
}): MembershipDecision {
  if (!args.signatureValid) return "drop";
  if (args.signerRole !== "admin") return "drop";
  if (args.incomingEpoch < 1 || !args.incomingHash) return "drop";
  if (!args.local) return "accept";
  if (args.incomingEpoch < args.local.epoch) return "stale";
  if (args.incomingEpoch === args.local.epoch) {
    return args.incomingHash === args.local.hash ? "unchanged" : "drop";
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
