import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { hashPin, verifyPin } from "@ollo/crypto";
import { config } from "../config.js";

export function hmacHex(pepper: string, value: string): string {
  return createHmac("sha256", pepper).update(value).digest("hex");
}

export function phoneHmac(e164: string): string {
  return hmacHex(config.phonePepper, e164);
}

export function sha256Hex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function randomId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString("hex")}`;
}

export function randomUuid(): string {
  return crypto.randomUUID();
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function otpCode(length: number): string {
  const max = 10 ** length;
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  let n = randomBytes(4).readUInt32BE(0);
  while (n >= limit) n = randomBytes(4).readUInt32BE(0);
  return (n % max).toString().padStart(length, "0");
}

export async function kdfHash(secret: string, pepper: string): Promise<string> {
  return hashPin(secret, pepper);
}

export async function kdfVerify(secret: string, pepper: string, stored: string): Promise<boolean> {
  return verifyPin(secret, pepper, stored);
}

export function safeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export interface AccessClaims {
  sub: string;
  did: string;
  exp: number;
  iat: number;
  jti: string;
}

export function signAccess(claims: Omit<AccessClaims, "iat" | "jti" | "exp">, ttlSec: number): string {
  const payload: AccessClaims = {
    ...claims,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttlSec,
    jti: randomBytes(8).toString("hex"),
  };
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", config.sessionKey).update(body).digest("base64url");
  return `${body}.${sig}`;
}

export function verifyAccess(token: string): AccessClaims | null {
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expected = createHmac("sha256", config.sessionKey).update(body).digest("base64url");
  if (!safeEqualStr(sig, expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as AccessClaims;
    if (claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch {
    return null;
  }
}
