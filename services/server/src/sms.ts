/**
 * OTP delivery. Production must use a real SMS provider. The OTP itself is
 * never logged. A stolen SMS channel can still register a new phone row;
 * it cannot mint a device on an already-keyed account (register-key).
 */
import { config } from "./config.js";

export interface SmsProvider {
  readonly name: string;
  sendOtp(phoneE164: string, otp: string): Promise<void>;
}

class NoneSms implements SmsProvider {
  readonly name = "none";
  async sendOtp(): Promise<void> {
    if (config.isProd) {
      throw new Error("SMS_PROVIDER=none is forbidden in production");
    }
  }
}

class TwilioSms implements SmsProvider {
  readonly name = "twilio";
  constructor(
    private readonly sid: string,
    private readonly token: string,
    private readonly from: string,
  ) {
    if (!sid || !token || !from) throw new Error("Twilio credentials missing");
  }

  async sendOtp(phoneE164: string, otp: string): Promise<void> {
    const url = `https://api.twilio.com/2010-04-01/Accounts/${this.sid}/Messages.json`;
    const body = new URLSearchParams({
      To: phoneE164,
      From: this.from,
      Body: `OllO code: ${otp}`,
    });
    const auth = Buffer.from(`${this.sid}:${this.token}`).toString("base64");
    const res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Basic ${auth}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    });
    if (!res.ok) {
      throw new Error(`Twilio ${res.status}`);
    }
  }
}

/** Generic HTTPS provider: POST JSON {to, body} with a bearer token. */
class HttpSms implements SmsProvider {
  readonly name = "http";
  constructor(
    private readonly endpoint: string,
    private readonly token: string,
  ) {
    if (!endpoint || !token) throw new Error("SMS HTTP endpoint/token missing");
  }

  async sendOtp(phoneE164: string, otp: string): Promise<void> {
    const res = await fetch(this.endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ to: phoneE164, body: `OllO code: ${otp}` }),
    });
    if (!res.ok) throw new Error(`SMS HTTP ${res.status}`);
  }
}

let cached: SmsProvider | null = null;

export function smsProvider(): SmsProvider {
  if (cached) return cached;
  const kind = config.smsProvider;
  if (kind === "twilio") {
    cached = new TwilioSms(config.twilioAccountSid, config.twilioAuthToken, config.twilioFromNumber);
  } else if (kind === "http") {
    cached = new HttpSms(config.smsHttpUrl, config.smsHttpToken);
  } else {
    cached = new NoneSms();
  }
  return cached;
}

export function resetSmsForTests(): void {
  cached = null;
}

/** Exported for unit tests — builds the Twilio form body without sending. */
export function twilioForm(phoneE164: string, otp: string, from: string): URLSearchParams {
  return new URLSearchParams({
    To: phoneE164,
    From: from,
    Body: `OllO code: ${otp}`,
  });
}
