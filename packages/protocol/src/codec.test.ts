import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { decodeSealed, encodeSealed, paddingBucket, type SealedPayload } from "./index.js";

describe("sealed codec", () => {
  it("round-trips a prekey whisper", () => {
    const p: SealedPayload = {
      version: 1,
      alg: "x3dh-dr-xchacha20poly1305-v1",
      header: { dhPublic: new Uint8Array(32).fill(7), previousChainLength: 3, messageNumber: 9 },
      prekey: {
        registrationId: 42,
        signedPrekeyId: 1,
        oneTimePrekeyId: 8,
        ephemeralPublic: new Uint8Array(32).fill(1),
        identityKeyX25519: new Uint8Array(32).fill(2),
      },
      nonce: new Uint8Array(24).fill(3),
      ciphertext: new Uint8Array(40).fill(4),
    };
    const again = decodeSealed(encodeSealed(p));
    assert.equal(again.header.messageNumber, 9);
    assert.equal(again.prekey?.oneTimePrekeyId, 8);
    assert.equal(again.ciphertext.length, 40);
  });

  it("pads to buckets", () => {
    assert.equal(paddingBucket(100), 256);
    assert.equal(paddingBucket(2000), 4096);
  });
});
