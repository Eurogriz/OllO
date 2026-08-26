import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateIdentity } from "./keys.js";
import { membershipHash, signMembership, verifyMembership } from "./membership.js";

describe("signed group membership", () => {
  it("is stable under member order and rejects a forged signature", () => {
    const admin = generateIdentity();
    const members = [
      { userId: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", role: "member" as const },
      { userId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", role: "admin" as const },
    ];
    const signed = signMembership({ groupId: "g1", epoch: 1, members }, admin);
    assert.equal(
      membershipHash("g1", 1, members),
      membershipHash("g1", 1, [members[1]!, members[0]!]),
    );
    assert.equal(
      verifyMembership({
        groupId: "g1",
        epoch: 1,
        members: signed.members,
        signerEd25519: admin.ed25519Public,
        signature: signed.signature,
      }),
      true,
    );
    const forged = signed.signature.slice();
    forged[0] = (forged[0] ?? 0) ^ 0xff;
    assert.equal(
      verifyMembership({
        groupId: "g1",
        epoch: 1,
        members: signed.members,
        signerEd25519: admin.ed25519Public,
        signature: forged,
      }),
      false,
    );
    const extra = [...signed.members, { userId: "cccccccc-cccc-cccc-cccc-cccccccccccc", role: "member" as const }];
    assert.notEqual(membershipHash("g1", 1, extra), signed.hash);
  });
});
