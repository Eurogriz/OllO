/**
 * Passphrase-wrapped account backup.
 *
 * Server stores only the opaque blob. The passphrase never leaves the device.
 * KDF is Argon2id (RFC 9106) with OWASP parameters; AEAD is XChaCha20-Poly1305.
 */
import { argon2id } from "@noble/hashes/argon2.js";
import { NONCE_LEN, TAG_LEN, aeadDecrypt, aeadEncrypt } from "./aead.js";
import { fromB64, randomBytes, toB64, utf8 } from "./bytes.js";

export const BACKUP_VERSION = 1 as const;
export const BACKUP_KDF = "argon2id" as const;

/** OWASP 2023: 19 MiB, 2 iterations, parallelism 1. */
export const BACKUP_ARGON2 = { t: 2, m: 19 * 1024, p: 1, dkLen: 32 } as const;

export interface SealedBackup {
  v: typeof BACKUP_VERSION;
  kdf: typeof BACKUP_KDF;
  t: number;
  m: number;
  p: number;
  salt: string;
  nonce: string;
  ciphertext: string;
}

export function sealBackup(passphrase: string, plaintext: Uint8Array): SealedBackup {
  if (passphrase.length < 8) throw new Error("backup passphrase too short");
  const salt = randomBytes(16);
  const key = argon2id(utf8(passphrase), salt, BACKUP_ARGON2);
  const aad = utf8("ollo-backup-v1");
  const { nonce, ciphertext } = aeadEncrypt(key, plaintext, aad);
  return {
    v: 1,
    kdf: "argon2id",
    t: BACKUP_ARGON2.t,
    m: BACKUP_ARGON2.m,
    p: BACKUP_ARGON2.p,
    salt: toB64(salt),
    nonce: toB64(nonce),
    ciphertext: toB64(ciphertext),
  };
}

export function openBackup(passphrase: string, blob: SealedBackup): Uint8Array {
  if (blob.v !== 1 || blob.kdf !== "argon2id") throw new Error("unsupported backup");
  const salt = fromB64(blob.salt);
  const key = argon2id(utf8(passphrase), salt, {
    t: blob.t,
    m: blob.m,
    p: blob.p,
    dkLen: 32,
  });
  return aeadDecrypt(key, fromB64(blob.nonce), fromB64(blob.ciphertext), utf8("ollo-backup-v1"));
}

export function encodeBackup(blob: SealedBackup): string {
  return JSON.stringify(blob);
}

export function decodeBackup(raw: string): SealedBackup {
  const j = JSON.parse(raw) as SealedBackup;
  if (!j || j.v !== 1 || typeof j.ciphertext !== "string") throw new Error("invalid backup");
  return j;
}

/**
 * Compact binary link (QR). Layout:
 *   1 byte version | 16 salt | 24 nonce | ciphertext (secret || tag)
 * Secret is 64 bytes: Ed25519 private || public. Fits QR v6 ECC-L.
 */
export const LINK_COMPACT_VERSION = 1;
export const LINK_COMPACT_SALT = 16;
export const LINK_AAD = "ollo-link-v1";

export function sealLinkCompact(passphrase: string, secret: Uint8Array): Uint8Array {
  if (passphrase.length < 8) throw new Error("backup passphrase too short");
  if (secret.length !== 64) throw new Error("invalid link secret");
  const salt = randomBytes(LINK_COMPACT_SALT);
  const key = argon2id(utf8(passphrase), salt, BACKUP_ARGON2);
  const { nonce, ciphertext } = aeadEncrypt(key, secret, utf8(LINK_AAD));
  const out = new Uint8Array(1 + salt.length + nonce.length + ciphertext.length);
  out[0] = LINK_COMPACT_VERSION;
  out.set(salt, 1);
  out.set(nonce, 1 + salt.length);
  out.set(ciphertext, 1 + salt.length + nonce.length);
  return out;
}

export function openLinkCompact(passphrase: string, blob: Uint8Array): Uint8Array {
  if (blob.length < 1 + LINK_COMPACT_SALT + NONCE_LEN + TAG_LEN + 64) throw new Error("invalid link");
  if (blob[0] !== LINK_COMPACT_VERSION) throw new Error("unsupported link");
  const salt = blob.slice(1, 1 + LINK_COMPACT_SALT);
  const nonce = blob.slice(1 + LINK_COMPACT_SALT, 1 + LINK_COMPACT_SALT + NONCE_LEN);
  const ciphertext = blob.slice(1 + LINK_COMPACT_SALT + NONCE_LEN);
  const key = argon2id(utf8(passphrase), salt, BACKUP_ARGON2);
  const secret = aeadDecrypt(key, nonce, ciphertext, utf8(LINK_AAD));
  if (secret.length !== 64) throw new Error("invalid link");
  return secret;
}
