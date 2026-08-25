# OllO API

Base URL: `/v1`. JSON over HTTPS. WebSocket at `/v1/realtime`.

Versioning: the prefix is the compatibility version. Additive changes stay
in `/v1`. Breaking changes go to `/v2`.

Auth: `Authorization: Bearer <access_token>` except for the auth bootstrap
endpoints.

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

### POST /v1/auth/request-otp

```json
{ "phone_e164": "+79991234567", "device_fingerprint": "hex" }
```

Response 200 (always, to reduce enumeration):

```json
{ "challenge_id": "ch_...", "expires_in": 300, "dev_otp": "123456" }
```

`dev_otp` is present **only** when `OTP_DEV_REVEAL=true`. Production images
compile this branch out.

### POST /v1/auth/verify-otp

```json
{
  "challenge_id": "ch_...",
  "otp": "123456",
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

Rotates the refresh token. Reuse of an old refresh revokes the family.

### POST /v1/auth/logout

### POST /v1/auth/logout-all

### POST /v1/auth/registration-lock

Set / change / remove Argon2id lock.

## Users

- `PUT /v1/me` — username, display name, about, avatar
- `GET /v1/me`
- `GET /v1/users/{id}`
- `GET /v1/users/by-username/{name}`
- `POST /v1/users/search` — exact username; phone match is hashed
- `POST /v1/contacts` / `DELETE /v1/contacts/{user_id}`
- `POST /v1/blocks` / `DELETE /v1/blocks/{user_id}`
- `POST /v1/reports`

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
- `GET /v1/presence/{user_id}` — coarse online / last-seen day
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

## Groups

- `POST /v1/groups`
- `GET /v1/groups/{id}`
- `POST /v1/groups/{id}/members`
- `DELETE /v1/groups/{id}/members/{user_id}`
- `POST /v1/groups/{id}/epoch` — bump after membership crypto rotation
- `POST /v1/groups/{id}/fanout` — copy one opaque ciphertext to every other member device
- `POST /v1/groups/{id}/invites`
- `POST /v1/groups/join/{token}`

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
Membership is required. A membership change increments `epoch`; clients must
redistribute Sender Keys over 1:1 sessions before the next group send.

## Attachments

- `POST /v1/attachments` → `{ upload_url, object_id, headers }`
- `POST /v1/attachments/{id}/complete` — `{ digest, size }`
- `GET /v1/attachments/{id}` → short-lived `{ download_url }`

Authorization for download: the requester must be the uploader or present
a `grant` issued inside a delivered envelope (HMAC of object_id with a
server grant key, carried in the E2EE message and shown on pull). Grants
are not guessable and are single-object.

## Calls

- `POST /v1/calls` — create `call_id`, issue TURN credentials
- `POST /v1/calls/{id}/end`
- Signaling payloads go through envelopes (`kind=call`)

## WebSocket `/v1/realtime`

Client → server:

```text
{ "op": "hello", "resume": "...", "after": "envelope_id" }
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

Delivery is at-least-once. Clients de-duplicate by envelope id.
