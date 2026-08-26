import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { QR_MAX_BYTES, qrModules, qrModulesFromBytes } from "./qr.ts";

describe("QR v1–6 ECC-L", () => {
  it("encodes a short string as v1 (21 modules)", () => {
    const mod = qrModules("ollo");
    assert.equal(mod.length, 21);
  });

  it("fits a 121-byte compact link in v6 (41 modules)", () => {
    const payload = new Uint8Array(121).fill(7);
    payload[0] = 1;
    const mod = qrModulesFromBytes(payload);
    assert.equal(mod.length, 41);
    assert.ok(payload.length <= QR_MAX_BYTES);
  });

  it("refuses a payload that would need v7 interleaving", () => {
    assert.throws(() => qrModulesFromBytes(new Uint8Array(200)));
  });
});
