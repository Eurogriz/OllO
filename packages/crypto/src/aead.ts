import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "./bytes.js";

export const NONCE_LEN = 24;
export const KEY_LEN = 32;
export const TAG_LEN = 16;

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  nonce: Uint8Array = randomBytes(NONCE_LEN),
): { nonce: Uint8Array; ciphertext: Uint8Array } {
  if (key.length !== KEY_LEN) throw new Error("bad aead key");
  if (nonce.length !== NONCE_LEN) throw new Error("bad nonce");
  const cipher = xchacha20poly1305(key, nonce, aad);
  return { nonce, ciphertext: cipher.encrypt(plaintext) };
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== KEY_LEN) throw new Error("bad aead key");
  if (nonce.length !== NONCE_LEN) throw new Error("bad nonce");
  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ciphertext);
}
