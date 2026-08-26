import { sha256 } from "@noble/hashes/sha256";
import { compare, concat, toHex } from "./bytes.js";

/**
 * Safety number: 60 decimal digits in 12 groups of 5, derived from the
 * sorted pair of identity public keys. Stable regardless of who computes it.
 */
export function safetyNumber(
  identityA: Uint8Array,
  identityB: Uint8Array,
): { digits: string; grouped: string; qr: string; hex: string } {
  const [first, second] = compare(identityA, identityB) <= 0 ? [identityA, identityB] : [identityB, identityA];
  const digest = sha256(concat(new TextEncoder().encode("ollo-safety-v1"), first, second));
  const hex = toHex(digest);
  let digits = "";
  for (let i = 0; i < 30; i++) {
    const n = digest[i]! % 10;
    digits += String(n);
  }
  // 60 digits: expand with a second hash so the UI matches Signal-style length
  const digest2 = sha256(concat(new TextEncoder().encode("ollo-safety-v1-b"), first, second));
  for (let i = 0; i < 30; i++) {
    digits += String(digest2[i]! % 10);
  }
  const groups: string[] = [];
  for (let i = 0; i < 60; i += 5) groups.push(digits.slice(i, i + 5));
  return {
    digits,
    grouped: groups.join(" "),
    qr: `ollo:safety:v1:${hex}`,
    hex,
  };
}

export function deviceListHash(identityKeys: Uint8Array[]): string {
  const sorted = [...identityKeys].sort(compare);
  const digest = sha256(concat(new TextEncoder().encode("ollo-devices-v1"), ...sorted));
  return toHex(digest);
}

/**
 * Roster hash includes device ids so a restored extra device with the same
 * identity keys is still visible. Sort by device id, then
 * `ollo-roster-v1 || id || 0x00 || IK_x25519 || 0x00` for each row.
 */
export function deviceRosterHash(devices: { deviceId: string; identityX25519: Uint8Array }[]): string {
  const sorted = [...devices].sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0));
  const parts: Uint8Array[] = [new TextEncoder().encode("ollo-roster-v1")];
  const z = new Uint8Array([0]);
  for (const d of sorted) {
    parts.push(new TextEncoder().encode(d.deviceId), z, d.identityX25519, z);
  }
  return toHex(sha256(concat(...parts)));
}
