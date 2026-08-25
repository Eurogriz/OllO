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
