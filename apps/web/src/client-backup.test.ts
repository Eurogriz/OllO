import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createLocalDevice, decodeBackup, encodeBackup, fromUtf8, generateEd25519, openBackup, sealBackup, utf8 } from "@ollo/crypto";
import { encodeUserUri } from "@ollo/shared";
import {
  accountAddress,
  accountFromSession,
  accountKeyFromBackup,
  backupPlaintext,
  createBackupFile,
  materialFromBackup,
} from "./client.ts";

function fakeAccount() {
  const mat = createLocalDevice();
  const account = generateEd25519();
  const acc = accountFromSession(
    {
      user: { id: "user-1", username: "alice" },
      device_id: "dev-1",
      access_token: "live-access-token-secret",
      refresh_token: "live-refresh-token-secret",
    },
    mat,
    account,
  );
  acc.messages = {
    peer: [
      {
        clientId: "m1",
        threadId: "peer",
        fromMe: true,
        senderUserId: "user-1",
        text: "секрет из истории",
        sentAt: new Date().toISOString(),
        status: "sent",
      },
    ],
  };
  acc.threads = [
    {
      id: "peer",
      kind: "direct",
      title: "peer",
      peerUserId: "peer",
      unread: 0,
      disappearingSeconds: 0,
    },
  ];
  return { acc, mat, account };
}

describe("account backup file", () => {
  it("omits live tokens and stores a dedicated account key", () => {
    const { acc, mat, account } = fakeAccount();
    assert.notDeepEqual(account.publicKey, mat.identity.ed25519Public);
    assert.equal(accountAddress(acc), encodeUserUri(account.publicKey));
    assert.notEqual(accountAddress(acc), encodeUserUri(mat.identity.ed25519Public));
    const raw = Buffer.from(backupPlaintext(acc)).toString("utf8");
    assert.equal(raw.includes("live-access-token-secret"), false);
    assert.equal(raw.includes("live-refresh-token-secret"), false);
    const file = createBackupFile(acc, "correct-horse");
    const opened = JSON.parse(fromUtf8(openBackup("correct-horse", decodeBackup(file)))) as {
      access: string;
      refresh: string;
      accountIdentity?: { publicKey: string };
    };
    assert.equal(opened.access, "");
    assert.equal(opened.refresh, "");
    assert.ok(opened.accountIdentity);
    const restored = materialFromBackup(file, "correct-horse");
    assert.deepEqual(restored.identity.ed25519Public, mat.identity.ed25519Public);
    assert.deepEqual(restored.identity.ed25519Private, mat.identity.ed25519Private);
    const recovered = accountKeyFromBackup(file, "correct-horse");
    assert.deepEqual(recovered.publicKey, account.publicKey);
    assert.deepEqual(recovered.privateKey, account.privateKey);
  });

  it("treats a pre-split backup's device Ed25519 as the account key", () => {
    const { acc, mat } = fakeAccount();
    const file = createBackupFile(acc, "correct-horse");
    const pt = JSON.parse(fromUtf8(openBackup("correct-horse", decodeBackup(file)))) as Record<string, unknown>;
    delete pt.accountIdentity;
    const legacy = encodeBackup(sealBackup("correct-horse", utf8(JSON.stringify(pt))));
    const recovered = accountKeyFromBackup(legacy, "correct-horse");
    assert.deepEqual(recovered.publicKey, mat.identity.ed25519Public);
    assert.deepEqual(recovered.privateKey, mat.identity.ed25519Private);
  });

  it("refuses a backup that still carries a session token", () => {
    const { acc } = fakeAccount();
    const file = createBackupFile(acc, "correct-horse");
    const blob = decodeBackup(file);
    const pt = JSON.parse(fromUtf8(openBackup("correct-horse", blob))) as Record<string, unknown>;
    pt.access = "stolen-access";
    const poisoned = encodeBackup(sealBackup("correct-horse", utf8(JSON.stringify(pt))));
    assert.throws(() => materialFromBackup(poisoned, "correct-horse"));
  });
});
