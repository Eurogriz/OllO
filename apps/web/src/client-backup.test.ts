import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createLocalDevice, decodeBackup, encodeBackup, fromUtf8, openBackup, sealBackup, utf8 } from "@ollo/crypto";
import { accountFromSession, backupPlaintext, createBackupFile, materialFromBackup } from "./client.ts";

function fakeAccount() {
  const mat = createLocalDevice();
  const acc = accountFromSession(
    {
      user: { id: "user-1", username: "alice" },
      device_id: "dev-1",
      access_token: "live-access-token-secret",
      refresh_token: "live-refresh-token-secret",
    },
    mat,
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
  return { acc, mat };
}

describe("account backup file", () => {
  it("omits live tokens and still yields the identity key", () => {
    const { acc, mat } = fakeAccount();
    const raw = Buffer.from(backupPlaintext(acc)).toString("utf8");
    assert.equal(raw.includes("live-access-token-secret"), false);
    assert.equal(raw.includes("live-refresh-token-secret"), false);
    const file = createBackupFile(acc, "correct-horse");
    const opened = JSON.parse(fromUtf8(openBackup("correct-horse", decodeBackup(file)))) as {
      access: string;
      refresh: string;
    };
    assert.equal(opened.access, "");
    assert.equal(opened.refresh, "");
    const restored = materialFromBackup(file, "correct-horse");
    assert.deepEqual(restored.identity.ed25519Public, mat.identity.ed25519Public);
    assert.deepEqual(restored.identity.ed25519Private, mat.identity.ed25519Private);
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
