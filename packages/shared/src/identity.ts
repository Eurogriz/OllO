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

/** Account address: the long-term identity Ed25519 public key, not a phone. */
export const USER_URI_PREFIX = "ollo:user:v1:";
export const AUTH_PROOF_DOMAIN = "ollo-auth-v1";

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(raw: string): Uint8Array | null {
  const t = raw.trim().replace(/-/g, "+").replace(/_/g, "/");
  if (!t || /[^A-Za-z0-9+/=]/.test(t)) return null;
  const pad = t.length % 4 === 0 ? t : t + "=".repeat(4 - (t.length % 4));
  try {
    const bin = atob(pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function encodeUserUri(ed25519Public: Uint8Array): string {
  if (planPublicKeyAccept(ed25519Public, ED25519_PUBLIC_LEN) !== "accept") return "";
  return `${USER_URI_PREFIX}${b64urlEncode(ed25519Public)}`;
}

export function parseUserUri(raw: string): Uint8Array | null {
  if (!raw) return null;
  const s = raw.trim();
  const payload = s.startsWith(USER_URI_PREFIX) ? s.slice(USER_URI_PREFIX.length) : s;
  const bytes = b64urlDecode(payload);
  if (!bytes || planPublicKeyAccept(bytes, ED25519_PUBLIC_LEN) !== "accept") return null;
  return bytes;
}

/** Canonical bytes signed to prove possession of the identity Ed25519 key. */
export function encodeAuthProof(challengeId: string, nonce: string): Uint8Array {
  if (!challengeId || !nonce) return new Uint8Array();
  const enc = new TextEncoder();
  const a = enc.encode(AUTH_PROOF_DOMAIN);
  const b = enc.encode(challengeId);
  const c = enc.encode(nonce);
  const out = new Uint8Array(a.length + 1 + b.length + 1 + c.length);
  out.set(a, 0);
  out[a.length] = 0;
  out.set(b, a.length + 1);
  out[a.length + 1 + b.length] = 0;
  out.set(c, a.length + 2 + b.length);
  return out;
}

export function planAuthProofAccept(args: {
  challengeId: string;
  nonce: string;
  signatureValid: boolean;
  expired?: boolean;
  consumed?: boolean;
}): "accept" | "drop" {
  if (!args.challengeId || !args.nonce) return "drop";
  if (args.expired || args.consumed) return "drop";
  if (!args.signatureValid) return "drop";
  return "accept";
}

/** Directory material for the account key and the device identity. */
export function planAccountProofKey(args: {
  accountEd25519: Uint8Array;
  deviceEd25519: Uint8Array;
}): "accept" | "drop" {
  if (planPublicKeyAccept(args.accountEd25519, ED25519_PUBLIC_LEN) !== "accept") return "drop";
  if (planPublicKeyAccept(args.deviceEd25519, ED25519_PUBLIC_LEN) !== "accept") return "drop";
  return "accept";
}

/** Prefer a dedicated account key; fall back to the device Ed25519 from an old backup. */
export function planAccountKeySource(args: {
  hasAccountIdentity: boolean;
  hasDeviceIdentity: boolean;
}): "account" | "device" | "drop" {
  if (args.hasAccountIdentity) return "account";
  if (args.hasDeviceIdentity) return "device";
  return "drop";
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/**
 * OTP must never copy the device IK onto the account and must never attach a
 * device to an already-keyed account (that requires register-key possession).
 * A dedicated incoming account key may be set once on a phone-only row.
 */
export function planOtpAccountBind(args: {
  incomingAccount: Uint8Array | null;
  storedAccount: Uint8Array | null;
  deviceEd25519: Uint8Array;
}): "set" | "keep" | "mismatch" | "drop" | "use-key" | "need-account" {
  const stored = args.storedAccount;
  if (stored && planPublicKeyAccept(stored, ED25519_PUBLIC_LEN) === "accept") {
    return "use-key";
  }
  const incoming = args.incomingAccount;
  if (!incoming) return "need-account";
  if (planPublicKeyAccept(incoming, ED25519_PUBLIC_LEN) !== "accept") return "drop";
  if (planPublicKeyAccept(args.deviceEd25519, ED25519_PUBLIC_LEN) !== "accept") return "drop";
  if (bytesEq(incoming, args.deviceEd25519)) return "drop";
  return "set";
}

/** Account-only link blob: add a device without history, tokens, or a device IK. */
export const LINK_URI_PREFIX = "ollo:link:v1:";

export function planLinkExport(args: { hasAccountIdentity: boolean }): "accept" | "drop" {
  return args.hasAccountIdentity ? "accept" : "drop";
}

export function planLinkAccept(args: {
  hasAccountIdentity: boolean;
  hasDeviceIdentity: boolean;
  access: string;
  refresh: string;
}): "accept" | "drop" {
  if (!args.hasAccountIdentity) return "drop";
  if (args.hasDeviceIdentity) return "drop";
  if (args.access || args.refresh) return "drop";
  return "accept";
}

export function encodeLinkUri(sealedJson: string): string {
  if (!sealedJson) return "";
  const bytes = new TextEncoder().encode(sealedJson);
  return `${LINK_URI_PREFIX}${b64urlEncode(bytes)}`;
}

export function parseLinkUri(raw: string): string | null {
  if (!raw) return null;
  const s = raw.trim();
  const payload = s.startsWith(LINK_URI_PREFIX) ? s.slice(LINK_URI_PREFIX.length) : s;
  const bytes = b64urlDecode(payload);
  if (!bytes || bytes.length === 0) return null;
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Restore always mints a fresh device identity. The account key is the recovery root. */
export function planRestoreDevice(args: {
  hasAccountIdentity: boolean;
  hasDeviceIdentity: boolean;
}): "new-device" | "drop" {
  if (planAccountKeySource(args) === "drop") return "drop";
  return "new-device";
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
