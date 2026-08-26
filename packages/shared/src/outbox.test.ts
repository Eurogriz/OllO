import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  OUTBOX_MAX_ATTEMPTS,
  SIGNED_PREKEY_MAX_AGE_MS,
  nextRetryDelayMs,
  afterUnauthorized,
  keepSignedPrekeyIds,
  onRefreshRejected,
  onSendFailure,
  planKeyFetch,
  planPrekeyReplenish,
  planSessionLaunch,
  planSignedPrekeyRotation,
  type OutboxItemView,
} from "./outbox.js";

describe("outbox state machine", () => {
  it("retries with exponential backoff then fails closed", () => {
    let item: OutboxItemView = { id: "m1", status: "pending", attempts: 0 };
    for (let i = 0; i < OUTBOX_MAX_ATTEMPTS - 1; i++) {
      item = onSendFailure(item);
      assert.equal(item.status, "retrying");
    }
    item = onSendFailure(item);
    assert.equal(item.status, "failed");
    assert.equal(item.attempts, OUTBOX_MAX_ATTEMPTS);
    assert.equal(nextRetryDelayMs(0), 1500);
    assert.equal(nextRetryDelayMs(3), 12000);
  });
});

describe("prekey consume planner", () => {
  it("skips the sending device and does not burn OPKs when a session exists", () => {
    assert.equal(
      planKeyFetch({
        localUserId: "u1",
        localDeviceId: "d1",
        targetUserId: "u1",
        targetDeviceId: "d1",
        hasSession: false,
      }),
      "skip-self",
    );
    assert.equal(
      planKeyFetch({
        localUserId: "u1",
        localDeviceId: "d1",
        targetUserId: "u2",
        targetDeviceId: "d9",
        hasSession: true,
      }),
      "use-session",
    );
    assert.equal(
      planKeyFetch({
        localUserId: "u1",
        localDeviceId: "d1",
        targetUserId: "u2",
        targetDeviceId: "d9",
        hasSession: false,
      }),
      "consume-bundle",
    );
  });
});

describe("prekey replenish planner", () => {
  it("uploads a batch only below the depth floor", () => {
    assert.equal(planPrekeyReplenish(20, 11), null);
    assert.deepEqual(planPrekeyReplenish(19, 11), { count: 100, startId: 11 });
    assert.equal(planPrekeyReplenish(5, 0), null);
  });
});

describe("refresh rejection", () => {
  it("wipes local state instead of retrying a reused refresh", () => {
    assert.equal(onRefreshRejected(), "wipe");
    assert.equal(afterUnauthorized(true), "retry");
    assert.equal(afterUnauthorized(false), "wipe");
  });
});

describe("signed prekey rotation planner", () => {
  it("rotates only after the max age and with a known createdAt", () => {
    const now = 1_700_000_000_000;
    assert.equal(planSignedPrekeyRotation({ currentId: 1, createdAtMs: now, now }), null);
    assert.equal(planSignedPrekeyRotation({ currentId: 1, now }), null);
    assert.equal(planSignedPrekeyRotation({ currentId: 0, createdAtMs: 1, now }), null);
    assert.deepEqual(
      planSignedPrekeyRotation({
        currentId: 1,
        createdAtMs: now - SIGNED_PREKEY_MAX_AGE_MS,
        now,
      }),
      { nextId: 2 },
    );
    assert.deepEqual(keepSignedPrekeyIds(5, [1, 2, 3, 4, 5]), [5, 4, 3]);
    assert.deepEqual(keepSignedPrekeyIds(2, [2]), [2]);
  });
});

describe("session launch", () => {
  it("skips OTP when the vault has a session and requires auth after wipe", () => {
    assert.equal(planSessionLaunch(true), "signed-in");
    assert.equal(planSessionLaunch(false), "need-auth");
  });
});
