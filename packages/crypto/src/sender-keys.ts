/**
 * Sender Keys (Signal group messaging).
 * https://signal.org/docs/specifications/group/#sender-keys
 *
 * Each sender has an independent chain. Distribution of the chain key
 * happens over existing 1:1 Double Ratchet sessions. Removing a member
 * requires a new epoch and fresh sender keys.
 */

import type { SealedPayload, SenderKeyDistribution } from "@ollo/protocol";
import { aeadDecrypt, aeadEncrypt } from "./aead.js";
import { fromB64, randomBytes, toB64, utf8 } from "./bytes.js";
import { kdf } from "./kdf.js";
import { type IdentityKeyPair, generateDh, sign, verify } from "./keys.js";

export interface SenderKeyState {
  groupId: string;
  epoch: number;
  chainId: string;
  chainKey: Uint8Array;
  iteration: number;
  signingPrivate: Uint8Array;
  signingPublic: Uint8Array;
}

export interface RemoteSenderKey {
  groupId: string;
  epoch: number;
  userId: string;
  deviceId: string;
  chainId: string;
  chainKey: Uint8Array;
  iteration: number;
  signingPublic: Uint8Array;
}

export function createSenderKey(groupId: string, epoch: number): SenderKeyState {
  const signing = generateDh();
  return {
    groupId,
    epoch,
    chainId: toB64(randomBytes(16)),
    chainKey: randomBytes(32),
    iteration: 0,
    signingPrivate: signing.privateKey,
    signingPublic: signing.publicKey,
  };
}

export function distributeSenderKey(
  state: SenderKeyState,
  identity: IdentityKeyPair,
): SenderKeyDistribution & { identitySignature: Uint8Array } {
  const body = utf8(`${state.groupId}|${state.epoch}|${state.chainId}|${state.iteration}`);
  return {
    groupId: state.groupId,
    epoch: state.epoch,
    chainId: state.chainId,
    chainKey: state.chainKey,
    iteration: state.iteration,
    signingKey: state.signingPublic,
    identitySignature: sign(identity.ed25519Private, body),
  };
}

export function acceptSenderKey(args: {
  dist: SenderKeyDistribution;
  identitySignature: Uint8Array;
  senderIdentityEd25519: Uint8Array;
  userId: string;
  deviceId: string;
}): RemoteSenderKey {
  const body = utf8(`${args.dist.groupId}|${args.dist.epoch}|${args.dist.chainId}|${args.dist.iteration}`);
  if (!verify(args.senderIdentityEd25519, body, args.identitySignature)) {
    throw new Error("sender key distribution signature invalid");
  }
  return {
    groupId: args.dist.groupId,
    epoch: args.dist.epoch,
    userId: args.userId,
    deviceId: args.deviceId,
    chainId: args.dist.chainId,
    chainKey: args.dist.chainKey,
    iteration: args.dist.iteration,
    signingPublic: args.dist.signingKey,
  };
}

function messageKey(chainKey: Uint8Array, iteration: number): { next: Uint8Array; mk: Uint8Array } {
  const next = kdf(chainKey, "ollo-sk-chain-v1", 32);
  const mk = kdf(chainKey, `ollo-sk-msg-v1:${iteration}`, 32);
  return { next, mk };
}

export function senderEncrypt(state: SenderKeyState, plaintext: Uint8Array): SealedPayload {
  const { next, mk } = messageKey(state.chainKey, state.iteration);
  const aad = utf8(`${state.groupId}:${state.epoch}:${state.chainId}:${state.iteration}`);
  const { nonce, ciphertext } = aeadEncrypt(mk, plaintext, aad);
  const header = {
    dhPublic: state.signingPublic,
    previousChainLength: state.epoch,
    messageNumber: state.iteration,
  };
  state.chainKey = next;
  state.iteration += 1;
  return {
    version: 1,
    alg: "senderkey-xchacha20poly1305-v1",
    header,
    nonce,
    ciphertext,
  };
}

export function senderDecrypt(remote: RemoteSenderKey, sealed: SealedPayload): Uint8Array {
  if (sealed.header.messageNumber < remote.iteration) {
    throw new Error("sender key iteration reused or old");
  }
  if (sealed.header.messageNumber - remote.iteration > 256) {
    throw new Error("too many skipped sender-key messages");
  }
  while (remote.iteration < sealed.header.messageNumber) {
    const stepped = messageKey(remote.chainKey, remote.iteration);
    remote.chainKey = stepped.next;
    remote.iteration += 1;
  }
  const { next, mk } = messageKey(remote.chainKey, remote.iteration);
  const aad = utf8(`${remote.groupId}:${remote.epoch}:${remote.chainId}:${remote.iteration}`);
  const pt = aeadDecrypt(mk, sealed.nonce, sealed.ciphertext, aad);
  remote.chainKey = next;
  remote.iteration += 1;
  return pt;
}

export function serializeSenderKey(s: SenderKeyState): string {
  return JSON.stringify({
    groupId: s.groupId,
    epoch: s.epoch,
    chainId: s.chainId,
    chainKey: toB64(s.chainKey),
    iteration: s.iteration,
    signingPrivate: toB64(s.signingPrivate),
    signingPublic: toB64(s.signingPublic),
  });
}

export function deserializeSenderKey(raw: string): SenderKeyState {
  const j = JSON.parse(raw) as Record<string, string | number>;
  return {
    groupId: String(j.groupId),
    epoch: Number(j.epoch),
    chainId: String(j.chainId),
    chainKey: fromB64(String(j.chainKey)),
    iteration: Number(j.iteration),
    signingPrivate: fromB64(String(j.signingPrivate)),
    signingPublic: fromB64(String(j.signingPublic)),
  };
}
