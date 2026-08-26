import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { WebSocket } from "ws";
import { shouldWake } from "../modules/notifications.js";
import { memoryRedis, publishBus, PUSH_CHANNEL, resetRedisForTests } from "../redis.js";
import {
  attach,
  detach,
  devicePresenceSeen,
  dropDevice,
  dropUser,
  HUB_INSTANCE,
  isDeviceOnline,
  isOnline,
  presenceSeen,
  pushToDevice,
  resetHub,
  startHubFanout,
} from "./hub.js";

function fakeWs(readyState: number): WebSocket {
  return { readyState, send() {}, close() {} } as unknown as WebSocket;
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
    attach(phone);
    assert.equal(dropDevice("d-phone"), 1);
    assert.equal(isDeviceOnline("d-phone"), false);
    assert.equal(isOnline("u1"), true);
    assert.equal(dropUser("u1"), 1);
    assert.equal(isOnline("u1"), false);
  });

  it("sees a remote presence key when this process has no socket", async () => {
    resetRedisForTests(memoryRedis());
    assert.equal(await presenceSeen("u-remote"), false);
    const { getRedis } = await import("../redis.js");
    const r = await getRedis();
    await r.setEx("presence:user:u-remote", 90, "d-remote");
    assert.equal(isOnline("u-remote"), false);
    assert.equal(await presenceSeen("u-remote"), true);
    resetRedisForTests();
  });

  it("sees a remote device presence key when this process has no socket", async () => {
    resetRedisForTests(memoryRedis());
    assert.equal(await devicePresenceSeen("d-remote"), false);
    const { getRedis } = await import("../redis.js");
    const r = await getRedis();
    await r.setEx("presence:device:d-remote", 90, "u-remote");
    assert.equal(isDeviceOnline("d-remote"), false);
    assert.equal(await devicePresenceSeen("d-remote"), true);
    resetRedisForTests();
  });

  it("delivers foreign bus frames and skips this process origin", async () => {
    resetRedisForTests(memoryRedis());
    const sent: string[] = [];
    attach({
      deviceId: "d-bus",
      userId: "u-bus",
      ws: {
        readyState: 1,
        send(data: string) {
          sent.push(String(data));
        },
        close() {},
      } as unknown as WebSocket,
      resume: "r-bus",
    });
    const stop = await startHubFanout();
    await publishBus(PUSH_CHANNEL, JSON.stringify({ origin: "other", deviceId: "d-bus", frame: { op: "x" } }));
    assert.equal(sent.length, 1);
    assert.equal(JSON.parse(sent[0]!).op, "x");
    await publishBus(PUSH_CHANNEL, JSON.stringify({ origin: HUB_INSTANCE, deviceId: "d-bus", frame: { op: "y" } }));
    assert.equal(sent.length, 1);
    const before = sent.length;
    pushToDevice("d-bus", { op: "local" });
    assert.equal(sent.length, before + 1);
    stop();
    resetRedisForTests();
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
