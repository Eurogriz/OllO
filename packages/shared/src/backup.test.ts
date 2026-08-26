import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { planBackupAccept, planBackupExport } from "./backup.js";

describe("backup export", () => {
  it("strips session secrets even when they were on the account", () => {
    const out = planBackupExport({ access: "live-access", refresh: "live-refresh" });
    assert.equal(out.access, "");
    assert.equal(out.refresh, "");
    assert.deepEqual(out.replay, { ids: [] });
    assert.deepEqual(out.outbox, []);
    assert.equal(JSON.stringify(out).includes("live-access"), false);
    assert.equal(JSON.stringify(out).includes("live-refresh"), false);
  });
});

describe("backup accept", () => {
  it("accepts identity-only material and drops a blob that still holds tokens", () => {
    assert.equal(planBackupAccept({ hasIdentity: true, access: "", refresh: "" }), "accept");
    assert.equal(planBackupAccept({ hasIdentity: false, access: "", refresh: "" }), "drop");
    assert.equal(planBackupAccept({ hasIdentity: true, access: "tok", refresh: "" }), "drop");
    assert.equal(planBackupAccept({ hasIdentity: true, access: "", refresh: "tok" }), "drop");
  });
});
