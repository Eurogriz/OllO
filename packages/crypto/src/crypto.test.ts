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
    tampered[3] ^= 1;
    assert.throws(() => decryptAttachment(enc, tampered));
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
});
