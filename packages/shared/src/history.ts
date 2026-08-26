/** Local disappearing-message GC. Ciphertext TTL on the server is separate. */
export function isExpired(expiresAt: string | undefined, now = Date.now()): boolean {
  if (!expiresAt) return false;
  const t = Date.parse(expiresAt);
  return Number.isFinite(t) && t <= now;
}

export function retainUnexpired<T extends { expiresAt?: string }>(items: T[], now = Date.now()): T[] {
  return items.filter((m) => !isExpired(m.expiresAt, now));
}
