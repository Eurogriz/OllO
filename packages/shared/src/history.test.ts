import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isExpired, retainUnexpired } from "./history.js";

describe("local history TTL", () => {
  it("drops expired rows and keeps live ones", () => {
    const now = 1_700_000_000_000;
    assert.equal(isExpired(undefined, now), false);
    assert.equal(isExpired(new Date(now - 1).toISOString(), now), true);
    assert.equal(isExpired(new Date(now + 1).toISOString(), now), false);
    const kept = retainUnexpired(
      [
        { id: "a", expiresAt: new Date(now - 5).toISOString() },
        { id: "b" },
        { id: "c", expiresAt: new Date(now + 5).toISOString() },
      ],
      now,
    );
    assert.deepEqual(
      kept.map((x) => x.id),
      ["b", "c"],
    );
  });
});
