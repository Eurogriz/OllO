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
  });
});
