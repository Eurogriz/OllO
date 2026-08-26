/**
 * Bounded FIFO of seen envelope ids. Delivery is at-least-once (WS + mailbox);
 * a duplicate must not re-apply receipts, deletes, or reactions.
 * Ids live on the device vault, never in a backup blob.
 */
export const REPLAY_CACHE_MAX = 4096;

export type ReplayDecision = "accept" | "drop";

export interface ReplayCache {
  ids: string[];
}

export function emptyReplayCache(): ReplayCache {
  return { ids: [] };
}

export function rememberEnvelope(
  cache: ReplayCache,
  envelopeId: string,
  max = REPLAY_CACHE_MAX,
): ReplayDecision {
  if (typeof envelopeId !== "string" || envelopeId.length === 0) return "drop";
  if (max < 1) return "drop";
  if (!Array.isArray(cache.ids)) cache.ids = [];
  if (cache.ids.includes(envelopeId)) return "drop";
  cache.ids.push(envelopeId);
  const extra = cache.ids.length - max;
  if (extra > 0) cache.ids.splice(0, extra);
  return "accept";
}
