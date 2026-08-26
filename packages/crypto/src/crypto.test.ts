import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { InnerMessage, PrekeyBundle } from "@ollo/protocol";
import { decodeSealed, encodeSealed } from "@ollo/protocol";
import {
  acceptSession,
  beginSession,
  createLocalDevice,
  decryptAttachment,
  decryptMessage,
  encryptAttachment,
  encryptFirstMessage,
  encryptMessage,
  safetyNumber,
  deserializeSession,
  serializeSession,
} from "./engine.js";
import { acceptSenderKey, createSenderKey, distributeSenderKey, senderDecrypt, senderEncrypt } from "./sender-keys.js";
import { generateIdentity } from "./keys.js";

function device(userId: string, deviceId: string) {
  const d = createLocalDevice();
  return { ...d, userId, deviceId };
}

function bundleOf(d: ReturnType<typeof device>): PrekeyBundle {
  const opk = d.oneTimePrekeys[0]!;
  return {
    userId: d.userId,
    deviceId: d.deviceId,
    registrationId: d.registrationId,
    identityKeyX25519: d.identity.x25519Public,
    identityKeyEd25519: d.identity.ed25519Public,
    signedPrekey: {
      id: d.signedPrekey.id,
      publicKey: d.signedPrekey.publicKey,
      signature: d.signedPrekey.signature,
    },
    oneTimePrekey: { id: opk.id, publicKey: opk.publicKey },
  };
}

function text(threadId: string, body: string): InnerMessage {
  return {
    version: 1,
    type: "text",
    clientId: crypto.randomUUID(),
    sentAt: new Date().toISOString(),
    threadId,
    text: body,
  };
}

describe("X3DH + Double Ratchet", () => {
  it("round-trips a first message and a reply", () => {
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const init = beginSession(alice, bundleOf(bob));
    const sealed = encryptFirstMessage(alice, init, text("t", "привет, это секрет"));
    const wire = encodeSealed(sealed);
    const received = decodeSealed(wire);
    const bobSession = acceptSession(bob, received, alice.userId, alice.deviceId);
    const opened = decryptMessage(bobSession, received);
    assert.equal(opened.text, "привет, это секрет");

    const reply = encryptMessage(bobSession, text("t", "принято"));
    const back = decryptMessage(init.session, reply);
    assert.equal(back.text, "принято");
  });

  it("handles out-of-order messages within the skip window", () => {
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const init = beginSession(alice, bundleOf(bob));
    const first = encryptFirstMessage(alice, init, text("t", "0"));
    const bobSession = acceptSession(bob, first, "alice", "a1");
    decryptMessage(bobSession, first);

    const m1 = encryptMessage(init.session, text("t", "one"));
    const m2 = encryptMessage(init.session, text("t", "two"));
    const m3 = encryptMessage(init.session, text("t", "three"));

    assert.equal(decryptMessage(bobSession, m3).text, "three");
    assert.equal(decryptMessage(bobSession, m1).text, "one");
    assert.equal(decryptMessage(bobSession, m2).text, "two");
  });

  it("provides forward secrecy: old message keys do not decrypt new mail", () => {
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const init = beginSession(alice, bundleOf(bob));
    const first = encryptFirstMessage(alice, init, text("t", "first"));
    const bobSession = acceptSession(bob, first, "alice", "a1");
    decryptMessage(bobSession, first);
    const later = encryptMessage(init.session, text("t", "later"));
    // Tamper: flip a ciphertext bit
    later.ciphertext[0] = later.ciphertext[0]! ^ 0xff;
    assert.throws(() => decryptMessage(bobSession, later));
  });

  it("rejects a forged signed prekey", () => {
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const bundle = bundleOf(bob);
    bundle.signedPrekey.signature = new Uint8Array(64);
    assert.throws(() => beginSession(alice, bundle));
  });

  it("archives the previous ratchet so in-flight mail still opens", () => {
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const init = beginSession(alice, bundleOf(bob));
    const first = encryptFirstMessage(alice, init, text("t", "first"));
    const bobSession = acceptSession(bob, first, "alice", "a1");
    decryptMessage(bobSession, first);
    const inFlight = encryptMessage(init.session, text("t", "in-flight"));

    const again = beginSession(alice, bundleOf(bob));
    const second = encryptFirstMessage(alice, again, text("t", "reset"));
    const replaced = acceptSession(bob, second, "alice", "a1", bobSession);
    assert.equal(decryptMessage(replaced, second).text, "reset");
    assert.equal(decryptMessage(replaced, inFlight).text, "in-flight");
    const more = encryptMessage(init.session, text("t", "after-promote"));
    assert.equal(decryptMessage(replaced, more).text, "after-promote");
    const wire = serializeSession(replaced);
    const round = deserializeSession(wire);
    assert.equal((round.previous ?? []).length, 1);
  });

  it("accepts a first message after signed-prekey rotation using the retired key", async () => {
    const { rotateSignedPrekey, SIGNED_PREKEY_KEEP } = await import("./engine.js");
    const alice = device("alice", "a1");
    const bob = device("bob", "b1");
    const stale = bundleOf(bob);
    rotateSignedPrekey(bob, 2);
    rotateSignedPrekey(bob, 3);
    assert.equal(bob.signedPrekey.id, 3);
    assert.equal(bob.previousSignedPrekeys.length, SIGNED_PREKEY_KEEP);
    assert.deepEqual(
      bob.previousSignedPrekeys.map((k) => k.id),
      [2, 1],
    );
    const init = beginSession(alice, stale);
    const sealed = encryptFirstMessage(alice, init, text("t", "ещё живо"));
    const bobSession = acceptSession(bob, sealed, alice.userId, alice.deviceId);
    assert.equal(decryptMessage(bobSession, sealed).text, "ещё живо");

    rotateSignedPrekey(bob, 4);
    assert.deepEqual(
      bob.previousSignedPrekeys.map((k) => k.id),
      [3, 2],
    );
    const carol = device("carol", "c1");
    const late = beginSession(carol, stale);
    const ghost = encryptFirstMessage(carol, late, text("t", "слишком старо"));
    assert.throws(() => acceptSession(bob, ghost, carol.userId, carol.deviceId));
  });
});

describe("Sender Keys", () => {
  it("distributes and decrypts a group message", () => {
    const alice = generateIdentity();
    const sk = createSenderKey("g1", 1);
    const dist = distributeSenderKey(sk, alice);
    const remote = acceptSenderKey({
      dist,
      identitySignature: dist.identitySignature,
      senderIdentityEd25519: alice.ed25519Public,
      userId: "alice",
      deviceId: "a1",
    });
    const sealed = senderEncrypt(sk, new TextEncoder().encode("group hi"));
    const pt = senderDecrypt(remote, sealed);
    assert.equal(new TextDecoder().decode(pt), "group hi");

    const next = senderEncrypt(sk, new TextEncoder().encode("again"));
    const forgedCt = new Uint8Array(next.ciphertext);
    forgedCt[0] = (forgedCt[0] ?? 0) ^ 0xff;
    const forged = { ...next, ciphertext: forgedCt };
    assert.throws(() => senderDecrypt(remote, forged));
  });

  it("new epoch after member removal uses a fresh chain", () => {
    const sk1 = createSenderKey("g1", 1);
    const sk2 = createSenderKey("g1", 2);
    assert.notEqual(Buffer.from(sk1.chainKey).toString("hex"), Buffer.from(sk2.chainKey).toString("hex"));
    assert.equal(sk2.epoch, 2);
  });
});

describe("Attachments", () => {
  it("encrypts and decrypts a file; tampering fails", () => {
    const file = new TextEncoder().encode("PDF-BYTES-SECRET");
    const enc = encryptAttachment(file, { mime: "application/pdf", filename: "doc.pdf" });
    const pt = decryptAttachment(enc, enc.ciphertext);
    assert.equal(new TextDecoder().decode(pt), "PDF-BYTES-SECRET");
    const tampered = new Uint8Array(enc.ciphertext);
    tampered[3] = (tampered[3] ?? 0) ^ 1;
    assert.throws(() => decryptAttachment(enc, tampered));
  });
});

describe("Encrypted backup", () => {
  it("round-trips and rejects a wrong passphrase or a tampered blob", async () => {
    const { sealBackup, openBackup, encodeBackup, decodeBackup } = await import("./backup.js");
    const secret = new TextEncoder().encode("identity-and-sessions");
    const blob = sealBackup("correct-horse-battery", secret);
    const wire = encodeBackup(blob);
    const again = openBackup("correct-horse-battery", decodeBackup(wire));
    assert.equal(new TextDecoder().decode(again), "identity-and-sessions");
    assert.throws(() => openBackup("wrong-passphrase-xx", blob));
    const tampered = {
      ...blob,
      ciphertext: `${blob.ciphertext.slice(0, -2)}${blob.ciphertext.endsWith("AA") ? "BB" : "AA"}`,
    };
    assert.throws(() => openBackup("correct-horse-battery", tampered));
  });
});

describe("Local vault", () => {
  it("seals identity material; a flipped bit or a wrong key fails", async () => {
    const { newVaultKey, sealVault, openVault } = await import("./vault.js");
    const key = newVaultKey();
    const pt = new TextEncoder().encode("x25519-private-must-not-be-plaintext");
    const blob = sealVault(key, pt);
    assert.equal(new TextDecoder().decode(openVault(key, blob)), "x25519-private-must-not-be-plaintext");
    const other = newVaultKey();
    assert.throws(() => openVault(other, blob));
    const bad = { ...blob, ciphertext: `${blob.ciphertext.slice(0, -2)}zz` };
    assert.throws(() => openVault(key, bad));
  });
});

describe("PIN / registration lock KDF", () => {
  it("verifies Argon2id and rejects a wrong PIN", async () => {
    const { hashPin, verifyPin } = await import("./pin.js");
    const stored = hashPin("lock-pin-ok", "pepper");
    assert.match(stored, /^argon2id\$/);
    assert.equal(verifyPin("lock-pin-ok", "pepper", stored), true);
    assert.equal(verifyPin("wrong-pin-xx", "pepper", stored), false);
    assert.equal(verifyPin("lock-pin-ok", "other-pepper", stored), false);
  });
});

describe("Safety number", () => {
  it("is stable regardless of argument order", () => {
    const a = generateIdentity();
    const b = generateIdentity();
    const s1 = safetyNumber(a.x25519Public, b.x25519Public);
    const s2 = safetyNumber(b.x25519Public, a.x25519Public);
    assert.equal(s1.digits, s2.digits);
    assert.equal(s1.digits.length, 60);
    assert.match(s1.qr, /^ollo:safety:v1:/);
  });

  it("roster hash includes device ids so a cloned identity is visible", async () => {
    const { deviceRosterHash } = await import("./safety.js");
    const ik = new Uint8Array(32).fill(1);
    const one = deviceRosterHash([{ deviceId: "d1", identityX25519: ik }]);
    const two = deviceRosterHash([
      { deviceId: "d1", identityX25519: ik },
      { deviceId: "d2", identityX25519: ik },
    ]);
    assert.notEqual(one, two);
    const swapped = deviceRosterHash([
      { deviceId: "d2", identityX25519: ik },
      { deviceId: "d1", identityX25519: ik },
    ]);
    assert.equal(two, swapped);
  });

  it("matches the published known-answer vector", () => {
    const a = new Uint8Array(32).fill(1);
    const b = new Uint8Array(32).fill(2);
    const s = safetyNumber(a, b);
    assert.equal(s.digits, "153665515321528787008757103930069366995789004059450082545955");
    assert.equal(s.hex, "f1d7e960a6cd69014103fcdd5ff23a894e93c8008057e107ab6e6795df5a9003");
    assert.equal(safetyNumber(b, a).digits, s.digits);
  });
});
