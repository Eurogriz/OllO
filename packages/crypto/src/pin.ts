/**
 * Registration-lock / local PIN hash. Argon2id with the same OWASP parameters
 * as encrypted backup. The pepper lives in the server secret store; the PIN
 * never does.
 */
import { argon2id } from "@noble/hashes/argon2.js";
import { BACKUP_ARGON2 } from "./backup.js";
import { equal, fromHex, randomBytes, toHex, utf8 } from "./bytes.js";

export const PIN_KDF = "argon2id" as const;

export function hashPin(pin: string, pepper: string): string {
  if (pin.length < 4 || pin.length > 128) throw new Error("pin length");
  const salt = randomBytes(16);
  const key = argon2id(utf8(`${pepper}:${pin}`), salt, BACKUP_ARGON2);
  return `${PIN_KDF}$${toHex(salt)}$${toHex(key)}`;
}

export function verifyPin(pin: string, pepper: string, stored: string): boolean {
  const [alg, saltHex, hashHex] = stored.split("$");
  if (alg !== PIN_KDF || !saltHex || !hashHex) return false;
  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = fromHex(saltHex);
    expected = fromHex(hashHex);
  } catch {
    return false;
  }
  const key = argon2id(utf8(`${pepper}:${pin}`), salt, BACKUP_ARGON2);
  return equal(key, expected);
}
