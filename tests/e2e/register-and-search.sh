#!/usr/bin/env bash
# E2E catalog: key-rooted signup, OTP-with-account, second device via
# register-key only. Requires a running server. Does not invent keys —
# uses the Node helper in this repo.
set -euo pipefail
BASE="${OLLO_BASE:-http://127.0.0.1:8080}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "health $(curl -sS "$BASE/healthz")"
curl -sS "$BASE/healthz" | grep -q '"ok":true'

cd "$ROOT"
node --import tsx --input-type=module <<'JS'
import { generateEd25519, sign, createLocalDevice } from "./packages/crypto/src/index.ts";
import { encodeAuthProof, encodeUserUri } from "./packages/shared/src/index.ts";

const BASE = process.env.OLLO_BASE || "http://127.0.0.1:8080";
const b64 = (u) => Buffer.from(u).toString("base64");
function device(name) {
  const mat = createLocalDevice();
  return {
    name,
    platform: "web",
    registration_id: mat.registrationId,
    identity_key_x25519: b64(mat.identity.x25519Public),
    identity_key_ed25519: b64(mat.identity.ed25519Public),
    signed_prekey: {
      id: mat.signedPrekey.id,
      public: b64(mat.signedPrekey.publicKey),
      signature: b64(mat.signedPrekey.signature),
    },
    one_time_prekeys: mat.oneTimePrekeys.slice(0, 5).map((k) => ({
      id: k.id,
      public: b64(k.publicKey),
    })),
  };
}
async function json(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json() };
}

const account = generateEd25519();
const ch = await json("POST", "/v1/auth/challenge", {});
if (ch.status !== 200) throw new Error("challenge " + ch.status);
const proof = encodeAuthProof(ch.body.challenge_id, ch.body.nonce);
const sig = sign(account.privateKey, proof);
const first = await json("POST", "/v1/auth/register-key", {
  challenge_id: ch.body.challenge_id,
  account_ed25519: b64(account.publicKey),
  signature: b64(sig),
  device: device("e2e-web"),
});
if (first.status !== 200) throw new Error("register-key " + JSON.stringify(first.body));
const tok = first.body.access_token;
const address = encodeUserUri(account.publicKey);
const found = await json("POST", "/v1/users/search", { address }, tok);
if (found.status !== 200 || !found.body.users?.length) throw new Error("search failed");

const otp = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990001999" });
const bare = await json("POST", "/v1/auth/verify-otp", {
  challenge_id: otp.body.challenge_id,
  otp: otp.body.dev_otp,
  device: device("e2e-otp-bare"),
});
if (bare.status !== 400) throw new Error("bare OTP must be 400, got " + bare.status);

const otp2 = await json("POST", "/v1/auth/request-otp", { phone_e164: "+79990001998" });
const withKey = await json("POST", "/v1/auth/verify-otp", {
  challenge_id: otp2.body.challenge_id,
  otp: otp2.body.dev_otp,
  account_ed25519: b64(generateEd25519().publicKey),
  device: device("e2e-otp"),
});
if (withKey.status !== 200) throw new Error("otp+account " + JSON.stringify(withKey.body));
console.log("e2e ok", address.slice(0, 24));
JS
