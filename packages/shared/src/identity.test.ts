import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ED25519_PUBLIC_LEN,
  ED25519_SIGNATURE_LEN,
  X25519_PUBLIC_LEN,
  noteRemoteIdentity,
  planDeviceDrop,
  planDeviceDropNotice,
  planPublicKeyAccept,
  planRosterPrune,
  planSessionAccept,
  planSessionOpen,
  planSessionArchive,
  planArchiveTrim,
  MAX_ARCHIVED_SESSIONS,
  encodeUserUri,
  parseUserUri,
  encodeAuthProof,
  planAuthProofAccept,
  planAccountProofKey,
  planAccountKeySource,
  planRestoreDevice,
  planOtpAccountBind,
  planLinkExport,
  planLinkAccept,
  encodeLinkUri,
  parseLinkUri,
  USER_URI_PREFIX,
  AUTH_PROOF_DOMAIN,
  LINK_URI_PREFIX,
} from "./identity.js";

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
    assert.equal(planSessionAccept({ userId: "u1", deviceId: "d2", droppedDevices: ["u1:d2"] }), "drop");
    assert.equal(planSessionAccept({ userId: "u1", deviceId: "d1", droppedDevices: ["u1:d2"] }), "accept");
    assert.equal(planSessionAccept({ userId: "u1", deviceId: "", droppedDevices: [] }), "drop");
    assert.equal(
      planDeviceDropNotice({
        senderUserId: "u1",
        senderDeviceId: "phone",
        targetUserId: "u1",
        targetDeviceId: "stolen",
        liveDeviceIds: ["phone"],
      }),
      "apply",
    );
    assert.equal(
      planDeviceDropNotice({
        senderUserId: "u1",
        senderDeviceId: "stolen",
        targetUserId: "u1",
        targetDeviceId: "phone",
        liveDeviceIds: ["phone", "stolen"],
      }),
      "drop",
    );
    assert.equal(
      planDeviceDropNotice({
        senderUserId: "eve",
        senderDeviceId: "d9",
        targetUserId: "u1",
        targetDeviceId: "phone",
        liveDeviceIds: ["phone"],
      }),
      "drop",
    );
    assert.equal(
      planDeviceDropNotice({
        senderUserId: "u1",
        senderDeviceId: "phone",
        targetUserId: "u1",
        targetDeviceId: "stolen",
      }),
      "drop",
    );
    const pub = new Uint8Array(X25519_PUBLIC_LEN).fill(7);
    assert.equal(planPublicKeyAccept(pub, X25519_PUBLIC_LEN), "accept");
    assert.equal(planPublicKeyAccept(pub, ED25519_PUBLIC_LEN), "accept");
    assert.equal(planPublicKeyAccept(new Uint8Array(3).fill(1), X25519_PUBLIC_LEN), "drop");
    assert.equal(planPublicKeyAccept(new Uint8Array(64).fill(1), X25519_PUBLIC_LEN), "drop");
    assert.equal(planPublicKeyAccept(new Uint8Array(X25519_PUBLIC_LEN), X25519_PUBLIC_LEN), "drop");
    assert.equal(planPublicKeyAccept(new Uint8Array(ED25519_SIGNATURE_LEN).fill(1), ED25519_SIGNATURE_LEN), "accept");
    assert.equal(planPublicKeyAccept(new Uint8Array(32).fill(1), 0), "drop");
    assert.equal(planSessionOpen({ hasSession: true, hasPrekey: true }), "accept-prekey");
    assert.equal(planSessionOpen({ hasSession: false, hasPrekey: true }), "accept-prekey");
    assert.equal(planSessionOpen({ hasSession: true, hasPrekey: false }), "use-session");
    assert.equal(planSessionOpen({ hasSession: false, hasPrekey: false }), "drop");
    assert.equal(planSessionArchive(true), "archive");
    assert.equal(planSessionArchive(false), "skip");
    assert.equal(MAX_ARCHIVED_SESSIONS, 40);
    assert.equal(planArchiveTrim(40), 0);
    assert.equal(planArchiveTrim(41), 1);
    assert.equal(planArchiveTrim(0), 0);
    assert.equal(planArchiveTrim(-1), 0);
    assert.equal(planArchiveTrim(10, 0), 0);
    const ik = new Uint8Array(ED25519_PUBLIC_LEN).fill(7);
    const uri = encodeUserUri(ik);
    assert.equal(uri.startsWith(USER_URI_PREFIX), true);
    assert.deepEqual(parseUserUri(uri), ik);
    assert.deepEqual(parseUserUri(uri.slice(USER_URI_PREFIX.length)), ik);
    assert.equal(parseUserUri(""), null);
    assert.equal(parseUserUri("ollo:user:v1:???"), null);
    assert.equal(encodeUserUri(new Uint8Array(ED25519_PUBLIC_LEN)), "");
    const proof = encodeAuthProof("ch_1", "nonce-a");
    assert.equal(new TextDecoder().decode(proof.slice(0, AUTH_PROOF_DOMAIN.length)), AUTH_PROOF_DOMAIN);
    assert.equal(encodeAuthProof("", "n").length, 0);
    assert.equal(planAuthProofAccept({ challengeId: "ch_1", nonce: "n", signatureValid: true }), "accept");
    assert.equal(planAuthProofAccept({ challengeId: "ch_1", nonce: "n", signatureValid: false }), "drop");
    assert.equal(planAuthProofAccept({ challengeId: "ch_1", nonce: "n", signatureValid: true, expired: true }), "drop");
    assert.equal(planAuthProofAccept({ challengeId: "", nonce: "n", signatureValid: true }), "drop");
    const live = new Uint8Array(ED25519_PUBLIC_LEN).fill(3);
    assert.equal(planAccountProofKey({ accountEd25519: live, deviceEd25519: new Uint8Array(ED25519_PUBLIC_LEN).fill(4) }), "accept");
    assert.equal(planAccountProofKey({ accountEd25519: new Uint8Array(ED25519_PUBLIC_LEN), deviceEd25519: live }), "drop");
    assert.equal(planAccountKeySource({ hasAccountIdentity: true, hasDeviceIdentity: true }), "account");
    assert.equal(planAccountKeySource({ hasAccountIdentity: false, hasDeviceIdentity: true }), "device");
    assert.equal(planAccountKeySource({ hasAccountIdentity: false, hasDeviceIdentity: false }), "drop");
    assert.equal(planRestoreDevice({ hasAccountIdentity: true, hasDeviceIdentity: false }), "new-device");
    assert.equal(planRestoreDevice({ hasAccountIdentity: false, hasDeviceIdentity: false }), "drop");
    const account = new Uint8Array(ED25519_PUBLIC_LEN).fill(5);
    const device = new Uint8Array(ED25519_PUBLIC_LEN).fill(6);
    assert.equal(planOtpAccountBind({ incomingAccount: account, storedAccount: null, deviceEd25519: device }), "set");
    assert.equal(planOtpAccountBind({ incomingAccount: device, storedAccount: null, deviceEd25519: device }), "drop");
    assert.equal(planOtpAccountBind({ incomingAccount: null, storedAccount: null, deviceEd25519: device }), "need-account");
    assert.equal(planOtpAccountBind({ incomingAccount: account, storedAccount: account, deviceEd25519: device }), "use-key");
    assert.equal(planOtpAccountBind({ incomingAccount: null, storedAccount: account, deviceEd25519: device }), "use-key");
    assert.equal(
      planOtpAccountBind({
        incomingAccount: new Uint8Array(ED25519_PUBLIC_LEN).fill(9),
        storedAccount: account,
        deviceEd25519: device,
      }),
      "use-key",
    );
    assert.equal(planLinkExport({ hasAccountIdentity: true }), "accept");
    assert.equal(planLinkExport({ hasAccountIdentity: false }), "drop");
    assert.equal(planLinkAccept({ hasAccountIdentity: true, hasDeviceIdentity: false, access: "", refresh: "" }), "accept");
    assert.equal(planLinkAccept({ hasAccountIdentity: true, hasDeviceIdentity: true, access: "", refresh: "" }), "drop");
    assert.equal(planLinkAccept({ hasAccountIdentity: true, hasDeviceIdentity: false, access: "tok", refresh: "" }), "drop");
    const linkUri = encodeLinkUri("{\"v\":1}");
    assert.equal(linkUri.startsWith(LINK_URI_PREFIX), true);
    assert.equal(parseLinkUri(linkUri), "{\"v\":1}");
    assert.equal(parseLinkUri(""), null);
  });
});
