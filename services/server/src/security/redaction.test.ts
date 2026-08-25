import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { redactObject } from "@ollo/shared";

describe("log redaction", () => {
  it("strips tokens, otp and keys", () => {
    const out = redactObject({
      otp: "123456",
      access_token: "abc",
      nested: { private_key: "x", ok: 1 },
      ciphertext: "AAAA",
    });
    assert.equal(out.otp, "[redacted]");
    assert.equal(out.access_token, "[redacted]");
    assert.equal((out.nested as { private_key: string }).private_key, "[redacted]");
    assert.equal((out.nested as { ok: number }).ok, 1);
    assert.equal(out.ciphertext, "[redacted]");
  });
});
