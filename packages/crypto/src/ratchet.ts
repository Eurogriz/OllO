/**
 * Double Ratchet as specified by Signal:
 * https://signal.org/docs/specifications/doubleratchet/
 *
 * KDF_RK and KDF_CK use HKDF-SHA-256 with domain-separated info strings.
 * AEAD is XChaCha20-Poly1305 (an AEAD permitted by the spec's construction).
 */

import type { RatchetHeader, SealedPayload } from "@ollo/protocol";
import { encodeSealed } from "@ollo/protocol";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { concat, fromB64, toB64, toHex } from "./bytes.js";
import { kdf } from "./kdf.js";
import { type DhKeyPair, type IdentityKeyPair, dh, generateDh } from "./keys.js";

export const MAX_SKIP = 256;

export interface SessionState {
  localUserId: string;
  localDeviceId: string;
  remoteUserId: string;
  remoteDeviceId: string;
  localIdentity: IdentityKeyPair;
  remoteIdentityX25519: Uint8Array;
  remoteIdentityEd25519: Uint8Array;
  rootKey: Uint8Array;
  sendChainKey: Uint8Array | null;
  recvChainKey: Uint8Array | null;
  sendN: number;
  recvN: number;
  prevChainLength: number;
  dhSend: DhKeyPair;
  dhRecvPub: Uint8Array | null;
  skipped: Record<string, string>;
  established: boolean;
}

export interface SerializedSession {
  v: 1;
  localUserId: string;
  localDeviceId: string;
  remoteUserId: string;
  remoteDeviceId: string;
  localIdentity: string;
  remoteIdentityX25519: string;
  remoteIdentityEd25519: string;
  rootKey: string;
  sendChainKey: string | null;
  recvChainKey: string | null;
  sendN: number;
  recvN: number;
  prevChainLength: number;
  dhSendPriv: string;
  dhSendPub: string;
  dhRecvPub: string | null;
  skipped: Record<string, string>;
  established: boolean;
}

function kdfRk(rootKey: Uint8Array, dhOut: Uint8Array): { root: Uint8Array; chain: Uint8Array } {
  const out = kdf(dhOut, "ollo-dr-rk-v1", 64, rootKey);
  return { root: out.slice(0, 32), chain: out.slice(32, 64) };
}

function kdfCk(chainKey: Uint8Array): { chain: Uint8Array; message: Uint8Array } {
  const out = kdf(chainKey, "ollo-dr-ck-v1", 64);
  return { chain: out.slice(0, 32), message: out.slice(32, 64) };
}

function skipKey(dhPub: Uint8Array, n: number): string {
  return `${toHex(dhPub)}:${n}`;
}

export function createInitiatorSession(args: {
  localUserId: string;
  localDeviceId: string;
  remoteUserId: string;
  remoteDeviceId: string;
  localIdentity: IdentityKeyPair;
  remoteIdentityX25519: Uint8Array;
  remoteIdentityEd25519: Uint8Array;
  rootKey: Uint8Array;
  remoteSignedPrekeyPublic: Uint8Array;
}): SessionState {
  const dhSend = generateDh();
  const { root, chain } = kdfRk(args.rootKey, dh(dhSend.privateKey, args.remoteSignedPrekeyPublic));
  return {
    localUserId: args.localUserId,
    localDeviceId: args.localDeviceId,
    remoteUserId: args.remoteUserId,
    remoteDeviceId: args.remoteDeviceId,
    localIdentity: args.localIdentity,
    remoteIdentityX25519: args.remoteIdentityX25519,
    remoteIdentityEd25519: args.remoteIdentityEd25519,
    rootKey: root,
    sendChainKey: chain,
    recvChainKey: null,
    sendN: 0,
    recvN: 0,
    prevChainLength: 0,
    dhSend,
    dhRecvPub: args.remoteSignedPrekeyPublic,
    skipped: {},
    established: true,
  };
}

export function createResponderSession(args: {
  localUserId: string;
  localDeviceId: string;
  remoteUserId: string;
  remoteDeviceId: string;
  localIdentity: IdentityKeyPair;
  remoteIdentityX25519: Uint8Array;
  remoteIdentityEd25519: Uint8Array;
  rootKey: Uint8Array;
  localSignedPrekey: DhKeyPair;
}): SessionState {
  return {
    localUserId: args.localUserId,
    localDeviceId: args.localDeviceId,
    remoteUserId: args.remoteUserId,
    remoteDeviceId: args.remoteDeviceId,
    localIdentity: args.localIdentity,
    remoteIdentityX25519: args.remoteIdentityX25519,
    remoteIdentityEd25519: args.remoteIdentityEd25519,
    rootKey: args.rootKey,
    sendChainKey: null,
    recvChainKey: null,
    sendN: 0,
    recvN: 0,
    prevChainLength: 0,
    dhSend: args.localSignedPrekey,
    dhRecvPub: null,
    skipped: {},
    established: true,
  };
}

function aadFor(state: SessionState, header: RatchetHeader): Uint8Array {
  // Canonical order so both parties derive the same AD.
  const a = state.localIdentity.x25519Public;
  const b = state.remoteIdentityX25519;
  const [first, second] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  return concat(
    first,
    second,
    header.dhPublic,
    u32(header.previousChainLength),
    u32(header.messageNumber),
  );
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  return a.length - b.length;
}

export function ratchetEncrypt(state: SessionState, plaintext: Uint8Array): SealedPayload {
  if (!state.sendChainKey) throw new Error("send chain not initialized");
  const { chain, message } = kdfCk(state.sendChainKey);
  const header: RatchetHeader = {
    dhPublic: state.dhSend.publicKey,
    previousChainLength: state.prevChainLength,
    messageNumber: state.sendN,
  };
  const { nonce, ciphertext } = aeadEncrypt(message, plaintext, aadFor(state, header));
  state.sendChainKey = chain;
  state.sendN += 1;
  return {
    version: 1,
    alg: "x3dh-dr-xchacha20poly1305-v1",
    header,
    nonce,
    ciphertext,
  };
}

export function ratchetDecrypt(state: SessionState, sealed: SealedPayload): Uint8Array {
  const skipped = trySkipped(state, sealed);
  if (skipped) return skipped;

  if (!state.dhRecvPub || !equalBytes(state.dhRecvPub, sealed.header.dhPublic)) {
    skipMessageKeys(state, sealed.header.previousChainLength);
    dhRatchet(state, sealed.header);
  }
  skipMessageKeys(state, sealed.header.messageNumber);
  if (!state.recvChainKey) throw new Error("recv chain not initialized");
  const { chain, message } = kdfCk(state.recvChainKey);
  state.recvChainKey = chain;
  state.recvN += 1;
  return aeadDecrypt(message, sealed.nonce, sealed.ciphertext, aadFor(state, sealed.header));
}

function trySkipped(state: SessionState, sealed: SealedPayload): Uint8Array | null {
  const k = skipKey(sealed.header.dhPublic, sealed.header.messageNumber);
  const mk = state.skipped[k];
  if (!mk) return null;
  delete state.skipped[k];
  return aeadDecrypt(fromB64(mk), sealed.nonce, sealed.ciphertext, aadFor(state, sealed.header));
}

function skipMessageKeys(state: SessionState, until: number): void {
  if (!state.recvChainKey) return;
  if (until - state.recvN > MAX_SKIP) {
    throw new Error("too many skipped messages");
  }
  while (state.recvN < until) {
    const { chain, message } = kdfCk(state.recvChainKey);
    state.recvChainKey = chain;
    const pub = state.dhRecvPub;
    if (!pub) throw new Error("missing dh recv");
    if (Object.keys(state.skipped).length >= MAX_SKIP) {
      throw new Error("skipped key window full");
    }
    state.skipped[skipKey(pub, state.recvN)] = toB64(message);
    state.recvN += 1;
  }
}

function dhRatchet(state: SessionState, header: RatchetHeader): void {
  state.prevChainLength = state.sendN;
  state.sendN = 0;
  state.recvN = 0;
  state.dhRecvPub = header.dhPublic;
  const recv = kdfRk(state.rootKey, dh(state.dhSend.privateKey, header.dhPublic));
  state.rootKey = recv.root;
  state.recvChainKey = recv.chain;
  state.dhSend = generateDh();
  const send = kdfRk(state.rootKey, dh(state.dhSend.privateKey, header.dhPublic));
  state.rootKey = send.root;
  state.sendChainKey = send.chain;
}

export function serializeSession(state: SessionState): SerializedSession {
  return {
    v: 1,
    localUserId: state.localUserId,
    localDeviceId: state.localDeviceId,
    remoteUserId: state.remoteUserId,
    remoteDeviceId: state.remoteDeviceId,
    localIdentity: JSON.stringify({
      x25519Private: toB64(state.localIdentity.x25519Private),
      x25519Public: toB64(state.localIdentity.x25519Public),
      ed25519Private: toB64(state.localIdentity.ed25519Private),
      ed25519Public: toB64(state.localIdentity.ed25519Public),
    }),
    remoteIdentityX25519: toB64(state.remoteIdentityX25519),
    remoteIdentityEd25519: toB64(state.remoteIdentityEd25519),
    rootKey: toB64(state.rootKey),
    sendChainKey: state.sendChainKey ? toB64(state.sendChainKey) : null,
    recvChainKey: state.recvChainKey ? toB64(state.recvChainKey) : null,
    sendN: state.sendN,
    recvN: state.recvN,
    prevChainLength: state.prevChainLength,
    dhSendPriv: toB64(state.dhSend.privateKey),
    dhSendPub: toB64(state.dhSend.publicKey),
    dhRecvPub: state.dhRecvPub ? toB64(state.dhRecvPub) : null,
    skipped: { ...state.skipped },
    established: state.established,
  };
}

export function deserializeSession(s: SerializedSession): SessionState {
  const id = JSON.parse(s.localIdentity) as Record<string, string>;
  return {
    localUserId: s.localUserId,
    localDeviceId: s.localDeviceId,
    remoteUserId: s.remoteUserId,
    remoteDeviceId: s.remoteDeviceId,
    localIdentity: {
      x25519Private: fromB64(id.x25519Private!),
      x25519Public: fromB64(id.x25519Public!),
      ed25519Private: fromB64(id.ed25519Private!),
      ed25519Public: fromB64(id.ed25519Public!),
    },
    remoteIdentityX25519: fromB64(s.remoteIdentityX25519),
    remoteIdentityEd25519: fromB64(s.remoteIdentityEd25519),
    rootKey: fromB64(s.rootKey),
    sendChainKey: s.sendChainKey ? fromB64(s.sendChainKey) : null,
    recvChainKey: s.recvChainKey ? fromB64(s.recvChainKey) : null,
    sendN: s.sendN,
    recvN: s.recvN,
    prevChainLength: s.prevChainLength,
    dhSend: { privateKey: fromB64(s.dhSendPriv), publicKey: fromB64(s.dhSendPub) },
    dhRecvPub: s.dhRecvPub ? fromB64(s.dhRecvPub) : null,
    skipped: { ...s.skipped },
    established: s.established,
  };
}

export function encodePayload(sealed: SealedPayload): Uint8Array {
  return encodeSealed(sealed);
}

function u32(n: number): Uint8Array {
  const o = new Uint8Array(4);
  const v = n >>> 0;
  o[0] = (v >>> 24) & 0xff;
  o[1] = (v >>> 16) & 0xff;
  o[2] = (v >>> 8) & 0xff;
  o[3] = v & 0xff;
  return o;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
