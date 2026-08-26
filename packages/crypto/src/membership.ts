/**
 * Signed group membership. Ed25519 over a domain-separated roster — the
 * same primitive as signed prekeys and sender-key distribution. Not a
 * new group ratchet (MLS remains the documented evolution path).
 *
 * A compromised server can still insert a SQL row. Clients refuse to
 * send sender keys or group ciphertext intent to anyone outside the
 * last valid signed roster.
 */
import { sha256 } from "@noble/hashes/sha256";
import { concat, toHex, utf8 } from "./bytes.js";
import { type IdentityKeyPair, sign, verify } from "./keys.js";

export const MEMBERSHIP_DOMAIN = "ollo-membership-v1";
export const MEMBERSHIP_ROLES = ["admin", "moderator", "member"] as const;
export type MembershipRole = (typeof MEMBERSHIP_ROLES)[number];

export interface MembershipMember {
  userId: string;
  role: MembershipRole;
}

export interface MembershipStatement {
  groupId: string;
  epoch: number;
  members: MembershipMember[];
}

export function isMembershipRole(role: string): role is MembershipRole {
  return (MEMBERSHIP_ROLES as readonly string[]).includes(role);
}

export function canonicalizeMembers(members: { userId: string; role: string }[]): MembershipMember[] {
  const seen = new Set<string>();
  const sorted = [...members].sort((a, b) => (a.userId < b.userId ? -1 : a.userId > b.userId ? 1 : 0));
  const out: MembershipMember[] = [];
  for (const m of sorted) {
    if (!m.userId || !isMembershipRole(m.role)) throw new Error("invalid membership row");
    if (seen.has(m.userId)) throw new Error("duplicate membership row");
    seen.add(m.userId);
    out.push({ userId: m.userId, role: m.role });
  }
  if (out.length === 0) throw new Error("empty membership");
  return out;
}

/** Canonical bytes signed by the admin identity Ed25519 key. */
export function encodeMembership(groupId: string, epoch: number, members: { userId: string; role: string }[]): Uint8Array {
  if (!groupId || epoch < 1) throw new Error("invalid membership statement");
  const rows = canonicalizeMembers(members);
  const z = new Uint8Array([0]);
  const parts: Uint8Array[] = [utf8(MEMBERSHIP_DOMAIN), z, utf8(groupId), z, utf8(String(epoch)), z];
  for (const m of rows) {
    parts.push(utf8(m.userId), z, utf8(m.role), z);
  }
  return concat(...parts);
}

export function membershipHash(groupId: string, epoch: number, members: { userId: string; role: string }[]): string {
  return toHex(sha256(encodeMembership(groupId, epoch, members)));
}

export function signMembership(
  statement: MembershipStatement,
  identity: IdentityKeyPair,
): MembershipStatement & { signature: Uint8Array; hash: string } {
  const members = canonicalizeMembers(statement.members);
  const body = encodeMembership(statement.groupId, statement.epoch, members);
  return {
    groupId: statement.groupId,
    epoch: statement.epoch,
    members,
    signature: sign(identity.ed25519Private, body),
    hash: toHex(sha256(body)),
  };
}

export function verifyMembership(args: {
  groupId: string;
  epoch: number;
  members: { userId: string; role: string }[];
  signerEd25519: Uint8Array;
  signature: Uint8Array;
}): boolean {
  try {
    const body = encodeMembership(args.groupId, args.epoch, args.members);
    return verify(args.signerEd25519, body, args.signature);
  } catch {
    return false;
  }
}
