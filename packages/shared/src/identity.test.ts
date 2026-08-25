import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { noteRemoteIdentity } from "./identity.js";

describe("remote identity guard", () => {
  it("treats a first-seen key as new and a mismatch as changed", () => {
    assert.equal(noteRemoteIdentity(undefined, "aa"), "new");
    assert.equal(noteRemoteIdentity("aa", "aa"), "unchanged");
    assert.equal(noteRemoteIdentity("aa", "bb"), "changed");
  });
});
