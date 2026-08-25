/**
 * X3DH as specified by Signal:
 * https://signal.org/docs/specifications/x3dh/
 *
 * Primitives: X25519, HKDF-SHA-256, Ed25519 signatures.
 * We do not change the DH combination order.
 */

import type { PrekeyBundle } from "@ollo/protocol";
import { concat } from "./bytes.js";
import { kdf } from "./kdf.js";
import {
  type DhKeyPair,
  type IdentityKeyPair,
  type OneTimePrekeyPair,
  type SignedPrekeyPair,
  dh,
  generateDh,
  verifySignedPrekey,
} from "./keys.js";

export interface X3dhInitResult {
  rootKey: Uint8Array;
  ephemeral: DhKeyPair;
  usedSignedPrekeyId: number;
  usedOneTimePrekeyId?: number;
  remoteIdentityX25519: Uint8Array;
  remoteIdentityEd25519: Uint8Array;
}

export interface X3dhAcceptInput {
  localIdentity: IdentityKeyPair;
  signedPrekey: SignedPrekeyPair;
  oneTimePrekey?: OneTimePrekeyPair;
  remoteIdentityX25519: Uint8Array;
  remoteEphemeralPublic: Uint8Array;
}

export function x3dhInitiate(
  local: IdentityKeyPair,
  bundle: PrekeyBundle,
): X3dhInitResult {
  if (
    !verifySignedPrekey(
      bundle.identityKeyEd25519,
      bundle.signedPrekey.publicKey,
      bundle.signedPrekey.signature,
    )
  ) {
    throw new Error("signed prekey signature invalid");
  }

  const ephemeral = generateDh();
  const dh1 = dh(local.x25519Private, bundle.signedPrekey.publicKey);
  const dh2 = dh(ephemeral.privateKey, bundle.identityKeyX25519);
  const dh3 = dh(ephemeral.privateKey, bundle.signedPrekey.publicKey);
  const parts = [dh1, dh2, dh3];
  let usedOneTimePrekeyId: number | undefined;
  if (bundle.oneTimePrekey) {
    parts.push(dh(ephemeral.privateKey, bundle.oneTimePrekey.publicKey));
    usedOneTimePrekeyId = bundle.oneTimePrekey.id;
  }
  const rootKey = kdf(concat(...parts), "ollo-x3dh-v1", 32);
  return {
    rootKey,
    ephemeral,
    usedSignedPrekeyId: bundle.signedPrekey.id,
    usedOneTimePrekeyId,
    remoteIdentityX25519: bundle.identityKeyX25519,
    remoteIdentityEd25519: bundle.identityKeyEd25519,
  };
}

export function x3dhAccept(input: X3dhAcceptInput): Uint8Array {
  const dh1 = dh(input.signedPrekey.privateKey, input.remoteIdentityX25519);
  const dh2 = dh(input.localIdentity.x25519Private, input.remoteEphemeralPublic);
  const dh3 = dh(input.signedPrekey.privateKey, input.remoteEphemeralPublic);
  const parts = [dh1, dh2, dh3];
  if (input.oneTimePrekey) {
    parts.push(dh(input.oneTimePrekey.privateKey, input.remoteEphemeralPublic));
  }
  return kdf(concat(...parts), "ollo-x3dh-v1", 32);
}
