import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { WebSocket } from "ws";
import { shouldWake } from "../modules/notifications.js";
import { attach, detach, isDeviceOnline, isOnline, resetHub } from "./hub.js";

function fakeWs(readyState: number): WebSocket {
  return { readyState, send() {} } as unknown as WebSocket;
}

describe("device online and wake kinds", () => {
  afterEach(() => {
    resetHub();
  });

  it("treats another device of the same user as a separate online check", () => {
    const phone = {
      deviceId: "d-phone",
      userId: "u1",
      ws: fakeWs(1),
      resume: "r1",
    };
    attach(phone);
    assert.equal(isOnline("u1"), true);
    assert.equal(isDeviceOnline("d-phone"), true);
    assert.equal(isDeviceOnline("d-tablet"), false);
    const tablet = {
      deviceId: "d-tablet",
      userId: "u1",
      ws: fakeWs(3),
      resume: "r2",
    };
    attach(tablet);
    assert.equal(isDeviceOnline("d-tablet"), false);
    detach(phone);
    assert.equal(isDeviceOnline("d-phone"), false);
    assert.equal(isOnline("u1"), true);
  });

  it("wakes only for messages and calls", () => {
    assert.equal(shouldWake("message"), true);
    assert.equal(shouldWake("msg"), true);
    assert.equal(shouldWake("call"), true);
    assert.equal(shouldWake("typing"), false);
    assert.equal(shouldWake("receipt"), false);
    assert.equal(shouldWake("control"), false);
  });
});
