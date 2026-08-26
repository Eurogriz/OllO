import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { redactObject } from "./index.js";

describe("shared redact", () => {
  it("hides otp", () => {
    assert.equal(redactObject({ otp: "000000" }).otp, "[redacted]");
  });
});
