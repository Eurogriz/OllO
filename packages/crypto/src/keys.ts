import { ed25519, x25519 } from "@noble/curves/ed25519";
import { concat, randomBytes, toB64, fromB64 } from "./bytes.js";

export interface IdentityKeyPair {
  x25519Private: Uint8Array;
  x25519Public: Uint8Array;
  ed25519Private: Uint8Array;
  ed25519Public: Uint8Array;
}

export interface DhKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface SignKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface SignedPrekeyPair {
  id: number;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface OneTimePrekeyPair {
  id: number;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateIdentity(): IdentityKeyPair {
  const x25519Private = x25519.utils.randomPrivateKey();
  const ed25519Private = ed25519.utils.randomPrivateKey();
  return {
    x25519Private,
    x25519Public: x25519.getPublicKey(x25519Private),
    ed25519Private,
    ed25519Public: ed25519.getPublicKey(ed25519Private),
  };
}

export function generateDh(): DhKeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function generateEd25519(): SignKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  return { privateKey, publicKey: ed25519.getPublicKey(privateKey) };
}

export function dh(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privateKey, publicKey);
}

export function sign(edPrivate: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, edPrivate);
}

export function verify(
  edPublic: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, edPublic);
}

/** Signed prekey signature is over the X25519 public key bytes. */
export function generateSignedPrekey(
  identity: IdentityKeyPair,
  id: number,
): SignedPrekeyPair {
  const pair = generateDh();
  const signature = sign(identity.ed25519Private, pair.publicKey);
  return { id, privateKey: pair.privateKey, publicKey: pair.publicKey, signature };
}

export function verifySignedPrekey(
  identityEd25519: Uint8Array,
  prekeyPublic: Uint8Array,
  signature: Uint8Array,
): boolean {
  return verify(identityEd25519, prekeyPublic, signature);
}

export function generateOneTimePrekeys(
  startId: number,
  count: number,
): OneTimePrekeyPair[] {
  const out: OneTimePrekeyPair[] = [];
  for (let i = 0; i < count; i++) {
    const pair = generateDh();
    out.push({ id: startId + i, privateKey: pair.privateKey, publicKey: pair.publicKey });
  }
  return out;
}

export function registrationId(): number {
  const b = randomBytes(4);
  return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 1;
}

export function serializeIdentity(id: IdentityKeyPair): string {
  return JSON.stringify({
    x25519Private: toB64(id.x25519Private),
    x25519Public: toB64(id.x25519Public),
    ed25519Private: toB64(id.ed25519Private),
    ed25519Public: toB64(id.ed25519Public),
  });
}

export function deserializeIdentity(s: string): IdentityKeyPair {
  const j = JSON.parse(s) as Record<string, string>;
  return {
    x25519Private: fromB64(j.x25519Private!),
    x25519Public: fromB64(j.x25519Public!),
    ed25519Private: fromB64(j.ed25519Private!),
    ed25519Public: fromB64(j.ed25519Public!),
  };
}

export function associatedData(
  localIk: Uint8Array,
  remoteIk: Uint8Array,
  extra: Uint8Array = new Uint8Array(),
): Uint8Array {
  return concat(localIk, remoteIk, extra);
}
