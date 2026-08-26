import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  planFanoutRecipients,
  planMembershipApply,
  planMembershipDelta,
  planMembershipSignerNotice,
  planDroppedDevices,
  planHeldSenderKeyFlush,
  planOwnOtherHoldDevices,
  planRejectedHashes,
  planGroupEpochAccept,
  planOwnSenderKeyEpochPrune,
  planOwnSenderKeyRotate,
  planSenderKeyEpochPrune,
  planSenderKeyEpochRotate,
  planSenderKeyIngest,
  planSenderKeyPrune,
  planSenderKeyShare,
  planSenderKeySharedDrop,
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

  it("keeps a refused roster hash rejected and flags another own device", () => {
    const alice = { userId: "a", role: "admin" };
    const eve = { userId: "eve", role: "member" };
    assert.deepEqual(planRejectedHashes(["aa"], "bb"), ["aa", "bb"]);
    assert.deepEqual(planRejectedHashes(["aa", "bb"], "aa"), ["bb", "aa"]);
    assert.equal(planRejectedHashes(Array.from({ length: 40 }, (_, i) => `h${i}`), "zz").length, 32);
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
        rejectedHashes: ["bb"],
      }),
      "rejected",
    );
    assert.equal(
      planMembershipApply({
        local: { epoch: 1, hash: "aa" },
        incomingEpoch: 2,
        incomingHash: "cc",
        signatureValid: true,
        signerRole: "admin",
        signerUserId: "a",
        localMembers: [alice],
        incomingMembers: [alice, eve],
        rejectedHashes: ["bb"],
      }),
      "confirm",
    );
    assert.equal(
      planMembershipSignerNotice({
        localUserId: "a",
        localDeviceId: "d1",
        signerUserId: "a",
        signerDeviceId: "d1",
      }),
      "self",
    );
    assert.equal(
      planMembershipSignerNotice({
        localUserId: "a",
        localDeviceId: "d1",
        signerUserId: "a",
        signerDeviceId: "stolen",
      }),
      "own-other-device",
    );
    assert.equal(
      planMembershipSignerNotice({
        localUserId: "a",
        localDeviceId: "d1",
        signerUserId: "b",
        signerDeviceId: "d9",
      }),
      "other-admin",
    );
  });

  it("confirms a first roster signed by another device and holds untrusted sender keys", () => {
    assert.equal(
      planMembershipApply({
        incomingEpoch: 1,
        incomingHash: "aa",
        signatureValid: true,
        signerRole: "admin",
        localDeviceId: "d1",
        signerDeviceId: "d1",
      }),
      "accept",
    );
    assert.equal(
      planMembershipApply({
        incomingEpoch: 1,
        incomingHash: "aa",
        signatureValid: true,
        signerRole: "admin",
        localDeviceId: "d1",
        signerDeviceId: "stolen",
      }),
      "confirm",
    );
    assert.equal(planSenderKeyIngest({ trustedUserIds: ["a", "b"], pendingUserIds: ["a", "b", "eve"], senderUserId: "b" }), "accept");
    assert.equal(planSenderKeyIngest({ trustedUserIds: ["a", "b"], pendingUserIds: ["a", "b", "eve"], senderUserId: "eve" }), "hold");
    assert.equal(planSenderKeyIngest({ trustedUserIds: ["a", "b"], pendingUserIds: ["a", "b"], senderUserId: "eve" }), "drop");
    assert.deepEqual(
      planHeldSenderKeyFlush(
        [
          { slot: "g:eve:d:1", userId: "eve" },
          { slot: "g:b:d:1", userId: "b" },
        ],
        ["a", "b"],
      ),
      { install: ["g:b:d:1"], discard: ["g:eve:d:1"] },
    );
    const slots = ["g1:alice:phone:1", "g1:alice:laptop:1", "g1:bob:d:1", "g2:alice:phone:2"];
    assert.deepEqual(planSenderKeyPrune(slots, { userId: "alice", deviceId: "phone" }).sort(), [
      "g1:alice:phone:1",
      "g2:alice:phone:2",
    ]);
    assert.deepEqual(planSenderKeyPrune(slots, { userId: "bob" }), ["g1:bob:d:1"]);
    assert.deepEqual(planDroppedDevices(["a:d1"], "a", "stolen"), ["a:d1", "a:stolen"]);
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["alice"],
        pendingUserIds: [],
        senderUserId: "alice",
        senderDeviceId: "phone",
        droppedDevices: ["alice:phone"],
      }),
      "drop",
    );
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: [],
        pendingUserIds: ["alice"],
        senderUserId: "alice",
        senderDeviceId: "phone",
        droppedDevices: ["alice:phone"],
      }),
      "drop",
    );
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["alice"],
        pendingUserIds: [],
        senderUserId: "alice",
        senderDeviceId: "laptop",
        droppedDevices: ["alice:phone"],
      }),
      "accept",
    );
    assert.deepEqual(planSenderKeyPrune(slots, {}), []);
    const existing = Array.from({ length: 64 }, (_, i) => `u:d${i}`);
    const bounded = planDroppedDevices(existing, "u", "new");
    assert.equal(bounded.length, 64);
    assert.equal(bounded[63], "u:new");
    assert.equal(bounded.includes("u:d0"), false);
    assert.deepEqual(
      planOwnOtherHoldDevices({
        localUserId: "a",
        localDeviceId: "d1",
        pending: [
          { signerUserId: "a", signerDeviceId: "stolen" },
          { signerUserId: "a", signerDeviceId: "d1" },
          { signerUserId: "b", signerDeviceId: "d9" },
        ],
      }),
      ["a:stolen"],
    );
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["a"],
        pendingUserIds: [],
        senderUserId: "a",
        senderDeviceId: "stolen",
        holdDevices: ["a:stolen"],
      }),
      "hold",
    );
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["a"],
        pendingUserIds: [],
        senderUserId: "a",
        senderDeviceId: "stolen",
        holdDevices: ["a:stolen"],
        droppedDevices: ["a:stolen"],
      }),
      "drop",
    );
    assert.deepEqual(
      planSenderKeyEpochRotate([
        { groupId: "g1", role: "admin", epoch: 2 },
        { groupId: "g2", role: "member", epoch: 4 },
        { groupId: "", role: "admin", epoch: 1 },
        { groupId: "g3", role: "admin", epoch: 0 },
      ]),
      [{ groupId: "g1", nextEpoch: 3 }],
    );
    assert.deepEqual(
      planOwnSenderKeyRotate([
        { groupId: "g1", role: "admin", epoch: 2 },
        { groupId: "g2", role: "member", epoch: 4 },
        { groupId: "g3", role: "moderator", epoch: 1 },
        { groupId: "", role: "member", epoch: 1 },
      ]),
      [
        { groupId: "g2", epoch: 4 },
        { groupId: "g3", epoch: 1 },
      ],
    );
    assert.equal(planGroupEpochAccept({ envelopeEpoch: 2, localEpoch: 2 }), "accept");
    assert.equal(planGroupEpochAccept({ envelopeEpoch: 1, localEpoch: 2 }), "drop");
    assert.equal(planGroupEpochAccept({ envelopeEpoch: 3, localEpoch: 2 }), "drop");
    assert.equal(planGroupEpochAccept({ envelopeEpoch: 2 }), "accept");
    assert.equal(planGroupEpochAccept({ envelopeEpoch: 0, localEpoch: 1 }), "drop");
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["alice"],
        pendingUserIds: [],
        senderUserId: "alice",
        incomingEpoch: 1,
        localEpoch: 2,
      }),
      "drop",
    );
    assert.equal(
      planSenderKeyIngest({
        trustedUserIds: ["alice"],
        pendingUserIds: [],
        senderUserId: "alice",
        incomingEpoch: 2,
        localEpoch: 2,
      }),
      "accept",
    );
    assert.deepEqual(
      planSenderKeyEpochPrune(
        ["g1:alice:phone:1", "g1:bob:d:2", "g2:alice:phone:1"],
        "g1",
        2,
      ).sort(),
      ["g1:alice:phone:1"],
    );
    assert.deepEqual(planOwnSenderKeyEpochPrune(["g1:1", "g1:2", "g10:2", "g1:2:x"], "g1", 2), ["g1:1"]);
    assert.deepEqual(
      planSenderKeyShare({
        liveAddresses: ["alice:phone", "bob:d1", "bob:d2", "alice:stolen"],
        alreadyShared: ["bob:d1", "carol:gone"],
        localAddress: "alice:phone",
        droppedDevices: ["alice:stolen"],
      }),
      { missing: ["bob:d2"], keep: ["bob:d1"] },
    );
    assert.deepEqual(
      planSenderKeySharedDrop({ "g1:2": ["bob:d1", "bob:d2"], "g2:1": ["bob:d2"] }, "bob:d2"),
      { "g1:2": ["bob:d1"], "g2:1": [] },
    );
  });
});
