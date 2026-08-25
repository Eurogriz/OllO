/**
 * High-level crypto engine used by clients.
 *
 * Native production apps should swap this for a libsignal-backed engine
 * that speaks the same envelope format. See CRYPTOGRAPHY.md.
 */

import type { InnerMessage, PrekeyBundle, SealedPayload } from "@ollo/protocol";
import { decodeSealed, encodeSealed } from "@ollo/protocol";
import {
  type EncryptedAttachment,
  decryptAttachment,
  encryptAttachment,
} from "./attachments.js";
import { fromB64 as fromB64Compat, fromUtf8, toB64 as toB64Compat, utf8 } from "./bytes.js";
import {
  type IdentityKeyPair,
  type OneTimePrekeyPair,
  type SignedPrekeyPair,
  generateIdentity,
  generateOneTimePrekeys,
  generateSignedPrekey,
  registrationId,
} from "./keys.js";
import {
  type SessionState,
  createInitiatorSession,
  createResponderSession,
  deserializeSession,
  ratchetDecrypt,
  ratchetEncrypt,
  serializeSession,
} from "./ratchet.js";
import { safetyNumber } from "./safety.js";
import {
  type RemoteSenderKey,
  type SenderKeyState,
  acceptSenderKey,
  createSenderKey,
  distributeSenderKey,
  senderDecrypt,
  senderEncrypt,
} from "./sender-keys.js";
import { x3dhAccept, x3dhInitiate } from "./x3dh.js";

export interface LocalDevice {
  userId: string;
  deviceId: string;
  registrationId: number;
  identity: IdentityKeyPair;
  signedPrekey: SignedPrekeyPair;
  /** Retired signed prekeys, newest first. Needed for in-flight X3DH. */
  previousSignedPrekeys: SignedPrekeyPair[];
  oneTimePrekeys: OneTimePrekeyPair[];
}

export const SIGNED_PREKEY_KEEP = 2;

export function retainSignedPrekeys(
  retired: SignedPrekeyPair,
  previous: SignedPrekeyPair[],
): SignedPrekeyPair[] {
  return [retired, ...previous.filter((k) => k.id !== retired.id)].slice(0, SIGNED_PREKEY_KEEP);
}

function lookupSignedPrekey(local: LocalDevice, id: number): SignedPrekeyPair {
  if (local.signedPrekey.id === id) return local.signedPrekey;
  const prev = (local.previousSignedPrekeys ?? []).find((k) => k.id === id);
  if (!prev) throw new Error("unknown signed prekey");
  return prev;
}

export function createLocalDevice(): Omit<LocalDevice, "userId" | "deviceId"> {
  const identity = generateIdentity();
  return {
    registrationId: registrationId(),
    identity,
    signedPrekey: generateSignedPrekey(identity, 1),
    previousSignedPrekeys: [],
    oneTimePrekeys: generateOneTimePrekeys(1, 100),
  };
}

export function rotateSignedPrekey(device: LocalDevice, nextId: number): void {
  device.previousSignedPrekeys = retainSignedPrekeys(
    device.signedPrekey,
    device.previousSignedPrekeys ?? [],
  );
  device.signedPrekey = generateSignedPrekey(device.identity, nextId);
}

export function replenishOneTimePrekeys(device: LocalDevice, nextId: number, count: number): void {
  device.oneTimePrekeys.push(...generateOneTimePrekeys(nextId, count));
}

export interface SessionInit {
  session: SessionState;
  usedSignedPrekeyId: number;
  usedOneTimePrekeyId?: number;
  ephemeralPublic: Uint8Array;
}

export function beginSession(local: LocalDevice, bundle: PrekeyBundle): SessionInit {
  const init = x3dhInitiate(local.identity, bundle);
  const session = createInitiatorSession({
    localUserId: local.userId,
    localDeviceId: local.deviceId,
    remoteUserId: bundle.userId,
    remoteDeviceId: bundle.deviceId,
    localIdentity: local.identity,
    remoteIdentityX25519: bundle.identityKeyX25519,
    remoteIdentityEd25519: bundle.identityKeyEd25519,
    rootKey: init.rootKey,
    remoteSignedPrekeyPublic: bundle.signedPrekey.publicKey,
  });
  return {
    session,
    usedSignedPrekeyId: init.usedSignedPrekeyId,
    usedOneTimePrekeyId: init.usedOneTimePrekeyId,
    ephemeralPublic: init.ephemeral.publicKey,
  };
}

export function acceptSession(
  local: LocalDevice,
  sealed: SealedPayload,
  remoteUserId: string,
  remoteDeviceId: string,
): SessionState {
  if (!sealed.prekey) throw new Error("missing prekey whisper");
  const opk = sealed.prekey.oneTimePrekeyId
    ? local.oneTimePrekeys.find((k) => k.id === sealed.prekey!.oneTimePrekeyId)
    : undefined;
  if (sealed.prekey.oneTimePrekeyId && !opk) {
    throw new Error("one-time prekey already consumed");
  }
  if (opk) {
    local.oneTimePrekeys = local.oneTimePrekeys.filter((k) => k.id !== opk.id);
  }
  const signedPrekey = lookupSignedPrekey(local, sealed.prekey.signedPrekeyId);
  const rootKey = x3dhAccept({
    localIdentity: local.identity,
    signedPrekey,
    oneTimePrekey: opk,
    remoteIdentityX25519: sealed.prekey.identityKeyX25519,
    remoteEphemeralPublic: sealed.prekey.ephemeralPublic,
  });
  return createResponderSession({
    localUserId: local.userId,
    localDeviceId: local.deviceId,
    remoteUserId,
    remoteDeviceId,
    localIdentity: local.identity,
    remoteIdentityX25519: sealed.prekey.identityKeyX25519,
    remoteIdentityEd25519: new Uint8Array(32),
    rootKey,
    localSignedPrekey: {
      privateKey: signedPrekey.privateKey,
      publicKey: signedPrekey.publicKey,
    },
  });
}

export function encryptMessage(session: SessionState, message: InnerMessage): SealedPayload {
  return ratchetEncrypt(session, utf8(JSON.stringify(reviveToJson(message))));
}

export function decryptMessage(session: SessionState, sealed: SealedPayload): InnerMessage {
  const pt = ratchetDecrypt(session, sealed);
  return JSON.parse(fromUtf8(pt), jsonReviver) as InnerMessage;
}

export function encryptFirstMessage(
  local: LocalDevice,
  init: SessionInit,
  message: InnerMessage,
): SealedPayload {
  const sealed = encryptMessage(init.session, message);
  sealed.prekey = {
    registrationId: 0,
    signedPrekeyId: init.usedSignedPrekeyId,
    oneTimePrekeyId: init.usedOneTimePrekeyId,
    ephemeralPublic: init.ephemeralPublic,
    identityKeyX25519: local.identity.x25519Public,
  };
  return sealed;
}

export function encryptGroupMessage(state: SenderKeyState, message: InnerMessage): SealedPayload {
  return senderEncrypt(state, utf8(JSON.stringify(reviveToJson(message))));
}

export function decryptGroupMessage(remote: RemoteSenderKey, sealed: SealedPayload): InnerMessage {
  return JSON.parse(fromUtf8(senderDecrypt(remote, sealed)), jsonReviver) as InnerMessage;
}

export {
  acceptSenderKey,
  createSenderKey,
  decodeSealed,
  decryptAttachment,
  deserializeSession,
  distributeSenderKey,
  encodeSealed,
  encryptAttachment,
  safetyNumber,
  serializeSession,
  type EncryptedAttachment,
  type RemoteSenderKey,
  type SenderKeyState,
  type SessionState,
};

function reviveToJson(message: InnerMessage): unknown {
  return JSON.parse(JSON.stringify(message, jsonReplacer));
}

function jsonReplacer(_k: string, v: unknown): unknown {
  if (v instanceof Uint8Array) return { __b: bytesToB64(v) };
  return v;
}

function jsonReviver(_k: string, v: unknown): unknown {
  if (v && typeof v === "object" && "__b" in (v as object)) {
    return b64ToBytes((v as { __b: string }).__b);
  }
  return v;
}

function bytesToB64(bytes: Uint8Array): string {
  return toB64Compat(bytes);
}

function b64ToBytes(b64: string): Uint8Array {
  return fromB64Compat(b64);
}
