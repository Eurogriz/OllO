import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { noteRemoteIdentity, planDeviceDrop, planRosterPrune } from "./identity.js";

describe("remote identity guard", () => {
  it("treats a first-seen key as new and a mismatch as changed", () => {
    assert.equal(noteRemoteIdentity(undefined, "aa"), "new");
    assert.equal(noteRemoteIdentity("aa", "aa"), "unchanged");
    assert.equal(noteRemoteIdentity("aa", "bb"), "changed");
  });

  it("drops sessions for devices that left the roster", () => {
    const keys = ["u1:d1", "u1:d2", "u10:d1", "u2:d9"];
    assert.deepEqual(planRosterPrune(keys, "u1", ["d1"]), ["u1:d2"]);
    assert.deepEqual(planRosterPrune(keys, "u1", ["d1", "d2"]), []);
    assert.deepEqual(planRosterPrune(keys, "", ["d1"]), []);
    assert.deepEqual(planDeviceDrop(keys, "u1", "d2"), ["u1:d2"]);
    assert.deepEqual(planDeviceDrop(keys, "u1", "missing"), []);
  });
});
