import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  OUTBOX_MAX_ATTEMPTS,
  nextRetryDelayMs,
  onSendFailure,
  planKeyFetch,
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
