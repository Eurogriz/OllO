import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { planMembershipApply, planTrustedMembers, sameMembership } from "./membership.js";

describe("membership apply planner", () => {
  it("drops unsigned, stale, and forked rosters", () => {
    assert.equal(
      planMembershipApply({ incomingEpoch: 1, incomingHash: "aa", signatureValid: false, signerRole: "admin" }),
      "drop",
    );
    assert.equal(
      planMembershipApply({ incomingEpoch: 1, incomingHash: "aa", signatureValid: true, signerRole: "member" }),
      "drop",
    );
    assert.equal(
      planMembershipApply({ incomingEpoch: 1, incomingHash: "aa", signatureValid: true, signerRole: "admin" }),
      "accept",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 2, hash: "bb" },
        incomingEpoch: 1,
        incomingHash: "aa",
        signatureValid: true,
        signerRole: "admin",
      }),
      "stale",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 2, hash: "bb" },
        incomingEpoch: 2,
        incomingHash: "bb",
        signatureValid: true,
        signerRole: "admin",
      }),
      "unchanged",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 2, hash: "bb" },
        incomingEpoch: 2,
        incomingHash: "cc",
        signatureValid: true,
        signerRole: "admin",
      }),
      "drop",
    );
  });

  it("never trusts a server-only extra member", () => {
    const plan = planTrustedMembers(["a", "b"], ["a", "b", "eve"]);
    assert.deepEqual(plan.trusted.sort(), ["a", "b"]);
    assert.deepEqual(plan.extra, ["eve"]);
    assert.deepEqual(plan.missing, []);
    assert.equal(
      sameMembership(
        [
          { userId: "b", role: "member" },
          { userId: "a", role: "admin" },
        ],
        [
          { userId: "a", role: "admin" },
          { userId: "b", role: "member" },
        ],
      ),
      true,
    );
  });
});
