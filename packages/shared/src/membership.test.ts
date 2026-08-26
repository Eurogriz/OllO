import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  planFanoutRecipients,
  planMembershipApply,
  planMembershipDelta,
  planTrustedMembers,
  sameMembership,
} from "./membership.js";

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
    assert.deepEqual(planFanoutRecipients(["a", "b"], ["a", "b", "eve"]).sort(), ["a", "b"]);
    assert.deepEqual(planFanoutRecipients([], ["a", "eve"]), []);
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

  it("confirms adds and drops a signer who was not a prior admin", () => {
    const alice = { userId: "a", role: "admin" };
    const bob = { userId: "b", role: "member" };
    const eve = { userId: "eve", role: "member" };
    assert.deepEqual(planMembershipDelta([alice], [alice, eve]).added, ["eve"]);
    assert.deepEqual(planMembershipDelta([alice, bob], [alice]).removed, ["b"]);
    assert.equal(
      planMembershipApply({
        local: { epoch: 1, hash: "aa" },
        incomingEpoch: 2,
        incomingHash: "bb",
        signatureValid: true,
        signerRole: "admin",
        signerUserId: "a",
        localMembers: [alice],
        incomingMembers: [alice, eve],
      }),
      "confirm",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 1, hash: "aa" },
        incomingEpoch: 2,
        incomingHash: "bb",
        signatureValid: true,
        signerRole: "admin",
        signerUserId: "a",
        localMembers: [alice, bob],
        incomingMembers: [alice],
      }),
      "accept",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 1, hash: "aa" },
        incomingEpoch: 2,
        incomingHash: "bb",
        signatureValid: true,
        signerRole: "admin",
        signerUserId: "a",
        localMembers: [alice, bob],
        incomingMembers: [
          { userId: "a", role: "admin" },
          { userId: "b", role: "admin" },
        ],
      }),
      "confirm",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 1, hash: "aa" },
        incomingEpoch: 2,
        incomingHash: "bb",
        signatureValid: true,
        signerRole: "admin",
        signerUserId: "eve",
        localMembers: [alice],
        incomingMembers: [
          { userId: "eve", role: "admin" },
          { userId: "a", role: "member" },
        ],
      }),
      "drop",
    );
  });
});
