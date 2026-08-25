import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { utf8 } from "./bytes.js";

export function kdf(
  ikm: Uint8Array,
  info: string,
  length: number,
  salt: Uint8Array = new Uint8Array(32),
): Uint8Array {
  return hkdf(sha256, ikm, salt, utf8(info), length);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export function sha256d(data: Uint8Array): Uint8Array {
  return sha256(data);
}
