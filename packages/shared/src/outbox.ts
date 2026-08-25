/**
 * Offline-first outbound state machine. Shared by web, Android, and iOS.
 * Native ports must keep the same transitions and limits.
 */
export const OUTBOX_MAX_ATTEMPTS = 8;
export const OUTBOX_BASE_DELAY_MS = 1500;

export type OutboxStatus =
  | "draft"
  | "pending"
  | "encrypted"
  | "uploading"
  | "sent"
  | "delivered"
  | "read"
  | "failed"
  | "retrying";

export interface OutboxItemView {
  id: string;
  status: OutboxStatus;
  attempts: number;
}

export function nextRetryDelayMs(attempts: number): number {
  const exp = Math.min(6, Math.max(0, attempts));
  return OUTBOX_BASE_DELAY_MS * 2 ** exp;
}

export function onSendFailure(item: OutboxItemView): OutboxItemView {
  const attempts = item.attempts + 1;
  if (attempts >= OUTBOX_MAX_ATTEMPTS) {
    return { ...item, attempts, status: "failed" };
  }
  return { ...item, attempts, status: "retrying" };
}

export function onEncrypted(item: OutboxItemView): OutboxItemView {
  return { ...item, status: "encrypted" };
}

export function onAccepted(item: OutboxItemView): OutboxItemView {
  return { ...item, status: "sent", attempts: item.attempts };
}

export type KeyPlan = "skip-self" | "use-session" | "consume-bundle";

/**
 * Never consume a one-time prekey when a Double Ratchet session already exists.
 * Never address the sending device.
 */
export function planKeyFetch(args: {
  localUserId: string;
  localDeviceId: string;
  targetUserId: string;
  targetDeviceId: string;
  hasSession: boolean;
}): KeyPlan {
  if (args.localUserId === args.targetUserId && args.localDeviceId === args.targetDeviceId) {
    return "skip-self";
  }
  return args.hasSession ? "use-session" : "consume-bundle";
}

export const PREKEY_MIN_DEPTH = 20;
export const PREKEY_BATCH = 100;

/** Upload a fresh batch only when the server-side unused OPK count is low. */
export function planPrekeyReplenish(remaining: number, nextId: number): { count: number; startId: number } | null {
  if (remaining >= PREKEY_MIN_DEPTH) return null;
  if (nextId < 1) return null;
  return { count: PREKEY_BATCH, startId: nextId };
}

/** Refresh reuse / revoke: drop local tokens and sealed state. Do not retry. */
export function onRefreshRejected(): "wipe" {
  return "wipe";
}

export const SIGNED_PREKEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Rotate the signed prekey about weekly. Unknown age is left alone. */
export function planSignedPrekeyRotation(args: {
  currentId: number;
  createdAtMs?: number;
  now?: number;
}): { nextId: number } | null {
  if (args.currentId < 1) return null;
  if (args.createdAtMs == null) return null;
  const now = args.now ?? Date.now();
  if (now - args.createdAtMs < SIGNED_PREKEY_MAX_AGE_MS) return null;
  return { nextId: args.currentId + 1 };
}
