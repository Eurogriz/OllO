import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { unwrapPushToken, wrapPushToken } from "./notifications.js";

describe("push token wrap", () => {
  it("round-trips a wrapped token and refuses plaintext", () => {
    const wrapped = wrapPushToken("fcm-device-token");
    assert.equal(unwrapPushToken(wrapped), "fcm-device-token");
    assert.equal(unwrapPushToken(Buffer.from("fcm-device-token", "utf8")), null);
    assert.equal(unwrapPushToken(Buffer.alloc(0)), null);
    const truncated = wrapped.subarray(0, 10);
    assert.equal(unwrapPushToken(truncated), null);
    const flipped = Buffer.from(wrapped);
    flipped[20] ^= 0xff;
    assert.equal(unwrapPushToken(flipped), null);
  });
});
