/**
 * Local-at-rest vault. Identity material and session state are sealed with
 * XChaCha20-Poly1305 under a 32-byte vault key. The key may itself be wrapped
 * with the user's PIN via `sealBackup` (Argon2id).
 *
 * Without a PIN the vault key is stored separately from the ciphertext so a
 * leaked account blob is not immediately greppable. A full origin dump still
 * yields the key — only a PIN (or hardware-backed wrap on native) resists
 * device seizure. Web is not a substitute for Keystore / Secure Enclave.
 */
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { fromB64, randomBytes, toB64, utf8 } from "./bytes.js";

export const VAULT_AAD = "ollo-vault-v1";

export interface SealedVault {
  v: 1;
  nonce: string;
  ciphertext: string;
}

export function newVaultKey(): Uint8Array {
  return randomBytes(32);
}

export function sealVault(key: Uint8Array, plaintext: Uint8Array): SealedVault {
  if (key.length !== 32) throw new Error("bad vault key");
  const { nonce, ciphertext } = aeadEncrypt(key, plaintext, utf8(VAULT_AAD));
  return { v: 1, nonce: toB64(nonce), ciphertext: toB64(ciphertext) };
}

export function openVault(key: Uint8Array, blob: SealedVault): Uint8Array {
  if (blob.v !== 1) throw new Error("unsupported vault");
  if (key.length !== 32) throw new Error("bad vault key");
  return aeadDecrypt(key, fromB64(blob.nonce), fromB64(blob.ciphertext), utf8(VAULT_AAD));
}

export function encodeVault(blob: SealedVault): string {
  return JSON.stringify(blob);
}

export function decodeVault(raw: string): SealedVault {
  const j = JSON.parse(raw) as SealedVault;
  if (!j || j.v !== 1 || typeof j.ciphertext !== "string") throw new Error("invalid vault");
  return j;
}
