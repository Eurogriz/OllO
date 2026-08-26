import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { emptyReplayCache, rememberEnvelope } from "./replay.js";

describe("envelope replay cache", () => {
  it("accepts a new id once and drops the rest", () => {
    const cache = emptyReplayCache();
    assert.equal(rememberEnvelope(cache, "e1"), "accept");
    assert.equal(rememberEnvelope(cache, "e1"), "drop");
    assert.equal(rememberEnvelope(cache, "e2"), "accept");
    assert.equal(rememberEnvelope(cache, ""), "drop");
    assert.deepEqual(cache.ids, ["e1", "e2"]);
  });

  it("evicts the oldest id when the bound is hit", () => {
    const cache = emptyReplayCache();
    assert.equal(rememberEnvelope(cache, "a", 2), "accept");
    assert.equal(rememberEnvelope(cache, "b", 2), "accept");
    assert.equal(rememberEnvelope(cache, "c", 2), "accept");
    assert.deepEqual(cache.ids, ["b", "c"]);
    assert.equal(rememberEnvelope(cache, "b", 2), "drop");
    assert.equal(rememberEnvelope(cache, "a", 2), "accept");
    assert.deepEqual(cache.ids, ["c", "a"]);
  });
});
