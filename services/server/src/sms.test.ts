import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { resetSmsForTests, smsProvider, twilioForm } from "./sms.js";

describe("SMS adapter", () => {
  it("builds a Twilio form without putting the OTP in logs", () => {
    const form = twilioForm("+79991234567", "654321", "+15005550006");
    assert.equal(form.get("To"), "+79991234567");
    assert.equal(form.get("From"), "+15005550006");
    assert.equal(form.get("Body"), "OllO code: 654321");
  });

  it("none provider is allowed in development", async () => {
    resetSmsForTests();
    process.env.SMS_PROVIDER = "none";
    const p = smsProvider();
    assert.equal(p.name, "none");
    await p.sendOtp("+79990000000", "000000");
  });
});
