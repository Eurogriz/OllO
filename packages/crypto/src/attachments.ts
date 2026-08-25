import { sha256 } from "@noble/hashes/sha256";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { randomBytes, utf8 } from "./bytes.js";

export interface EncryptedAttachment {
  ciphertext: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  digest: Uint8Array;
  size: number;
  mime: string;
  filename: string;
}

export function encryptAttachment(
  plaintext: Uint8Array,
  meta: { mime: string; filename: string },
): EncryptedAttachment {
  const key = randomBytes(32);
  const aad = utf8(`${meta.filename}\n${meta.mime}`);
  const { nonce, ciphertext } = aeadEncrypt(key, plaintext, aad);
  return {
    ciphertext,
    key,
    nonce,
    digest: sha256(ciphertext),
    size: ciphertext.length,
    mime: meta.mime,
    filename: meta.filename,
  };
}

export function decryptAttachment(
  enc: EncryptedAttachment,
  ciphertext: Uint8Array,
): Uint8Array {
  const digest = sha256(ciphertext);
  if (digest.length !== enc.digest.length) throw new Error("digest mismatch");
  let d = 0;
  for (let i = 0; i < digest.length; i++) d |= digest[i]! ^ enc.digest[i]!;
  if (d !== 0) throw new Error("digest mismatch");
  const aad = utf8(`${enc.filename}\n${enc.mime}`);
  return aeadDecrypt(enc.key, enc.nonce, ciphertext, aad);
}

export const MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024;

export const ALLOWED_MIME_PREFIXES = [
  "image/",
  "video/",
  "audio/",
  "application/pdf",
  "application/zip",
  "application/vnd.openxmlformats",
  "text/plain",
  "application/octet-stream",
];

export function isAllowedMime(mime: string): boolean {
  return ALLOWED_MIME_PREFIXES.some((p) => mime === p || mime.startsWith(p));
}
