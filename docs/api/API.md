# OllO API

Base URL: `/v1`. JSON over HTTPS. WebSocket at `/v1/realtime`.

Versioning: the prefix is the compatibility version. Additive changes stay
in `/v1`. Breaking changes go to `/v2`.

Auth: `Authorization: Bearer <access_token>` except for the auth bootstrap
endpoints. Tokens must never appear in URLs or query strings.

Idempotency: mutating endpoints accept `Idempotency-Key: <uuid>`. Replays
return the original result for 24 hours.

Pagination: cursor-based. `?cursor=<opaque>&limit=50`. Never use offset.

Errors:

```json
{
  "error": {
    "code": "otp_invalid",
    "message": "Invalid or expired code",
    "request_id": "req_..."
  }
}
```

`message` is safe to show. `code` is stable.

Rate limit headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`,
`Retry-After`.

Full machine-readable spec: [`openapi.yaml`](openapi.yaml).

## Auth

Identity is an **account** Ed25519 keypair. The private key never leaves
the device (or its sealed backup). The public key is the account address
(`ollo:user:v1:<b64url>`). Each device also has its own X3DH identity
(X25519 + Ed25519). Restore and a second device mint a new device
identity and prove the same account key.

### POST /v1/auth/challenge

```json
{}
```

Response 200:

```json
{ "challenge_id": "ch_...", "nonce": "...", "expires_in": 300 }
```

The client signs `ollo-auth-v1 || 0x00 || challenge_id || 0x00 || nonce`
with the **account** Ed25519 private key. These two endpoints are limited
per client IP (30 challenges / 10 register-key per minute).

### POST /v1/auth/register-key

```json
{
  "challenge_id": "ch_...",
  "account_ed25519": "b64",
  "signature": "b64",
  "registration_lock": null,
  "device": {
    "name": "Pixel 8",
    "platform": "android",
    "identity_key_x25519": "b64",
    "identity_key_ed25519": "b64",
    "signed_prekey": { "id": 1, "public": "b64", "signature": "b64" },
    "one_time_prekeys": [{ "id": 1, "public": "b64" }]
  }
}
```

Response is the same session object as `verify-otp`. A matching
`account_ed25519` adds another device (registration lock if set).

### POST /v1/auth/request-otp

```json
{ "phone_e164": "+79991234567", "device_fingerprint": "hex" }
```

Response 200 (always, to reduce enumeration):

```json
{ "challenge_id": "ch_...", "expires_in": 300, "dev_otp": "123456" }
```

`dev_otp` is present **only** when `OTP_DEV_REVEAL=true`. Production images
compile this branch out. OTP is not the account root: the first device
identity is never copied onto `account_ed25519`.

### POST /v1/auth/verify-otp

```json
{
  "challenge_id": "ch_...",
  "otp": "123456",
  "account_ed25519": "b64",
  "registration_lock": null,
  "device": {
    "name": "Pixel 8",
    "platform": "android",
    "identity_key_x25519": "b64",
    "identity_key_ed25519": "b64",
    "signed_prekey": { "id": 1, "public": "b64", "signature": "b64" },
    "one_time_prekeys": [{ "id": 1, "public": "b64" }]
  }
}
```

`account_ed25519` is optional. If present it must be distinct from the
device Ed25519 (`planOtpAccountBind` → `drop` otherwise) and is written
only when the user has none (`set`). A mismatch with the stored account
is 400. OTP never copies the device identity onto the account.

Response:

```json
{
  "user": { "id": "...", "username": null, "is_new": true },
  "device_id": "...",
  "access_token": "...",
  "refresh_token": "...",
  "access_expires_in": 900
}
```

### POST /v1/auth/refresh

Rotates the refresh token. Reuse of an old refresh revokes the family
(every live refresh in that family returns 401). Clients must wipe local
session secrets (`onRefreshRejected`).

### POST /v1/auth/logout

### POST /v1/auth/logout-all

### POST /v1/auth/registration-lock

Set / change / remove Argon2id lock.

## Users

- `PUT /v1/me` — username, display name, about, avatar. Username may change at most 3 times per rolling 24 hours (`429 rate_limited`). Repeating the current username is not counted.
- `GET /v1/me` — includes `address` (`ollo:user:v1:…`) when the account key is set
- `GET /v1/users/{id}`
- `GET /v1/users/by-username/{name}`
- `POST /v1/users/search` — exact username **or** `address` / `identity_ed25519`. Phone lookup is refused (403); contact discovery is on-device and mutual.
- `POST /v1/me/delete` — mark the account deleted, revoke devices/sessions, drop OPKs and mailboxes. Access of those devices is rejected immediately.
- `POST /v1/contacts` / `DELETE /v1/contacts/{user_id}`
- `POST /v1/blocks` / `DELETE /v1/blocks/{user_id}`
- `POST /v1/reports` — `{ user_id, reason: spam|abuse|other }`. Metadata only; no message bodies.

## Devices and keys

- `GET /v1/devices`
- `DELETE /v1/devices/{id}`
- `GET /v1/keys/{user_id}` — prekey bundles (`?consume=0` does not take one-time prekeys)
- `GET /v1/keys/{user_id}/devices` — device list without consuming prekeys
- `GET /v1/keys/{user_id}/{device_id}` — consume one bundle for that device
- `PUT /v1/keys/signed-prekey`
- `POST /v1/keys/one-time` — replenish
- `GET /v1/me/prekey-depth`
- `GET /v1/safety/{user_id}` — public identity material for verification
- `GET /v1/presence/{user_id}` — coarse online / last-seen **day**. Only the
  subject or a contact of the subject. Anyone else gets a uniform
  `{ state: "offline", last_seen_day: null }` (no existence oracle beyond
  that the id is well-formed).
- `GET /v1/notifications/pending` — sealed wakeup count, no bodies

## Messaging

- `POST /v1/envelopes` — submit one or more sealed envelopes
- `GET /v1/envelopes?cursor=&limit=` — drain mailbox (also used after WS drop)
- `POST /v1/envelopes/ack` — `{ "ids": ["..."] }`

Envelope (server-visible schema):

```json
{
  "id": "uuidv7",
  "recipient_user_id": "...",
  "recipient_device_id": "...",
  "kind": "message|receipt|typing|call|control",
  "ciphertext": "b64",
  "padding_bucket": 1024,
  "ttl_seconds": 0
}
```

`ciphertext` is opaque. The server does not parse the inner payload.

Sealed push is sent only for `message` and `call`, and only if that
recipient **device** has no live WebSocket. Typing / receipt / control
never wake the OS.

## Groups

- `POST /v1/groups` — `{ id?, member_ids, membership }` (`membership` is required)
- `GET /v1/groups/{id}` — includes server rows **and** the last signed `membership`
- `POST /v1/groups/{id}/members` — `{ user_id, role?, membership }`
- `DELETE /v1/groups/{id}/members/{user_id}` — body `{ membership }`
- `POST /v1/groups/{id}/epoch` — `{ membership }` after sender-key rotation
- `POST /v1/groups/{id}/fanout` — copy one opaque ciphertext to every other member device
- `POST /v1/groups/{id}/invites`
- `POST /v1/groups/join/{token}` — consumes the invite into `pending_joins`; no live member row and no epoch bump until an admin re-signs via `POST /members`

Fan-out body (server never parses the inner payload):

```json
{
  "kind": "message",
  "ciphertext": "b64",
  "padding_bucket": 1024,
  "ttl_seconds": 0
}
```

The same ciphertext is stored once per recipient device (except the sender device).
Fan-out copies only to `planFanoutRecipients` (signed roster ∩ live members).
A membership change increments `epoch`; clients must redistribute Sender Keys
over 1:1 sessions before the next group send. Mutations except invite-join
require `membership`: `{ epoch, members[{user_id,role}], signer_user_id,
signer_device_id, signature }` — Ed25519 over `ollo-membership-v1`. Clients
ignore server-only extra members (`planTrustedMembers`).

## Attachments

- `POST /v1/attachments` → `{ upload_url, object_id, headers }`
- `POST /v1/attachments/{id}/complete` — `{ digest, size }`
- `GET /v1/attachments/{id}` → short-lived `{ download_url }`

Authorization for download: the requester must be the uploader or present
a `grant` issued inside a delivered envelope (HMAC of object_id with a
server grant key, carried in the E2EE message and shown on pull). Grants
are not guessable and are single-object.

## Calls

- `POST /v1/calls` — `{ media, participant_user_ids?, group_id? }` → `call_id` + time-limited ICE/TURN
- `POST /v1/calls/{id}/join` — callee registers their own device (never the caller's)
- `GET /v1/calls/{id}` — metadata only, no SDP
- `GET /v1/me/calls` — recent rooms this device participated in
- `POST /v1/calls/{id}/end` — any participant
- Signaling (offer / answer / ICE / hangup / SFrame key) goes through E2EE envelopes (`kind=call`)

TURN credentials are coturn REST (`expiry:userId` + HMAC-SHA1). Static shared
passwords are not issued in production.

## Backups

- `PUT /v1/backups` — `{ blob }` opaque ciphertext (Argon2id + XChaCha20-Poly1305 on the client)
- `GET /v1/backups/latest` — last sealed blob for this user

The server never receives the passphrase. Keep at most 3 blobs per user.

## WebSocket `/v1/realtime`

Open `WSS /v1/realtime` with **no** query parameters. Browsers cannot set
`Authorization` on WebSocket; they send the access token in the first
`hello` frame. Native clients may instead send `Authorization: Bearer`
on the upgrade. Query `access_token` is ignored.

Client → server:

```text
{ "op": "hello", "access_token": "...", "resume": "...", "after": "envelope_id" }
{ "op": "ack", "ids": ["..."] }
{ "op": "ping" }
```

Server → client:

```text
{ "op": "welcome", "resume": "...", "server_time": "..." }
{ "op": "envelope", "envelope": { ... } }
{ "op": "presence", "user_id": "...", "state": "online|offline" }
{ "op": "pong" }
{ "op": "error", "code": "..." }
```

Delivery is at-least-once. Clients de-duplicate by envelope id
(`rememberEnvelope`, 4096 most-recent ids in the device vault). A duplicate
is still ACKed so the mailbox drains. Replay ids are not written into
backups.
