const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** Username: 3–32 chars, latin/digit/underscore, must start with a letter. */
export const USERNAME_RE = /^[a-z][a-z0-9_]{2,31}$/;

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

export function isValidUsername(raw: string): boolean {
  return USERNAME_RE.test(normalizeUsername(raw));
}

/** Very small E.164 check. We do not invent a phone parser. */
export const E164_RE = /^\+[1-9][0-9]{6,14}$/;

export function isValidE164(raw: string): boolean {
  return E164_RE.test(raw.trim());
}

export function randomClientId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
