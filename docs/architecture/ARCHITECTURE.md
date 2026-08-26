# OllO Architecture

Document status: normative for implementation.
Last updated: 2026-08-25.

## 1. Goals and non-goals

### Goals

- End-to-end encryption for messages, attachments, and call signaling.
- Server is a store-and-forward + fan-out + abuse-control plane. It cannot
  decrypt user content even if fully compromised.
- Multi-device with per-device identity keys.
- Offline-first clients with durable outbound queues.
- Horizontal scale of stateless API/realtime nodes.
- Operable: health, metrics, traces, backups, staged rollouts.

### Non-goals

- Absolute anonymity or onion routing. That is a different product.
- Homegrown cryptographic primitives or a “Signal-like” protocol invented here.
- Reading user mail for ads, ranking, or centralized moderation of content.
- Claiming “Signal-level security” before independent audit.

## 2. High-level diagram

```text
                    +------------------+
   Android/iOS/Web  |  Clients         |
   (E2EE, local DB) |  libsignal/noble |
                    +--------+---------+
                             | HTTPS + WSS
                             v
                    +------------------+
                    |  API Gateway     |  TLS, WAF, rate limit,
                    |  (edge / ingress)|  authn, request id
                    +--------+---------+
                             |
          +------------------+------------------+
          v                  v                  v
   +-------------+   +--------------+   +---------------+
   | Auth/Users  |   | Messaging    |   | Attachments   |
   | Devices/Keys|   | Groups/Calls |   | Notifications |
   +------+------+   +------+-------+   +-------+-------+
          |                 |                    |
          v                 v                    v
   +------------+    +-------------+     +--------------+
   | PostgreSQL |    | Redis       |     | Object store |
   | metadata   |    | presence,   |     | ciphertext   |
   | envelopes  |    | ratelimit,  |     | blobs only   |
   |            |    | pubsub,     |     +--------------+
   +------------+    | streams     |
                     +-------------+
                             |
                             v
                     +---------------+
                     | FCM / APNs    |  sealed push
                     | coturn TURN   |  media relay
                     +---------------+
```

All application services in this repository currently run as a **modular
monolith** (`services/server`). Module boundaries match the boxes above and
are import-safe (no cross-module table access except through published ports).

## 3. Why a modular monolith

| Option | Pros | Cons | Decision |
|---|---|---|---|
| Microservices from day one | Independent deploy | Distributed txs, 10× ops, harder audit | Rejected for v1 |
| Modular monolith | One threat surface to review, simple txs, easy local run | Must keep module discipline | **Chosen** |
| Split later by load | Scale the hot path only | Requires clean ports | Planned |

Split triggers (documented, not speculative):

- Messaging WebSocket CPU saturates independently of auth → extract `messaging`.
- Attachment bandwidth dominates → extract `attachments` + dedicated object path.
- Multi-region fan-out needs its own queue cluster → extract dispatcher.

Until then, scale by **stateless replicas** + PostgreSQL primary/replica +
Redis Cluster + S3.

## 4. Technology choices

| Concern | Choice | Why | Rejected |
|---|---|---|---|
| API language | TypeScript / Node 22 | Shared protocol types with web, strict types, Fastify perf | Python (weaker long-lived WS), Go (better scale, worse type share here) |
| HTTP | Fastify 5 | Schema, hooks, low overhead | Express (legacy), Nest (magic) |
| Realtime | WebSocket (native) | Persistent, resume tokens, binary frames | MQTT (extra broker), gRPC streaming (mobile NAT) |
| DB | PostgreSQL 16 | ACID, partitioning, PITR | Cassandra (ops), Cockroach (cost) |
| Local DB driver | PGlite | Real Postgres, no Docker for dev | SQLite dialect drift |
| Cache / queue | Redis + Streams | Presence, rate limit, pubsub, lightweight queue | Kafka (overkill until multi-region) |
| Objects | S3 API / MinIO / local disk | Ciphertext only | Filesystem on app nodes |
| Client crypto (native) | Official libsignal | Audited implementation | Homegrown ratchet |
| Client crypto (TS/web) | @noble + spec X3DH/DR | Audited primitives; protocol needs review | tweetnacl (older) |
| Local client DB | SQLCipher | AES-256 at rest | Unencrypted SQLite |
| Calls | WebRTC + SFrame | Standard, NAT, codecs | Homegrown media |
| Infra | Terraform + k8s + Helm | Standard production path | Click-ops |
| Observability | OTEL + Prometheus | Privacy-aware metrics | Logging message bodies |

## 5. Trust boundaries

```text
[User device] --TLS--> [Edge] --mTLS/private--> [App] --TLS--> [PG/Redis/S3]
     ^                                                     |
     |                  ciphertext only                    |
     +------------ never send keys this way ---------------+
```

- Device private keys never leave the device (except encrypted backup, if the
  user explicitly enables it — off by default).
- Server processes have no capability that yields plaintext.
- Push providers receive a wake token, never a body.
- TURN sees media ciphertext when E2EE media is enabled; still sees IPs.

## 6. Client architecture

### Android

- Language: Kotlin 2, minSdk 26, targetSdk 35
- UI: Jetpack Compose, Material 3, dark/light
- Architecture: modular (`:app`, `:core:crypto`, `:core:database`,
  `:core:network`, `:feature:auth`, `:feature:chat`, `:feature:calls`,
  `:feature:settings`)
- DI: Hilt
- Async: Coroutines + WorkManager (upload/download)
- DB: SQLCipher + SQLDelight
- Keys: Android Keystore, StrongBox if present
- Calls: WebRTC native
- Push: FCM data messages (no notification body)

### iOS

- Language: Swift 5.10 / 6
- UI: SwiftUI
- Architecture: same module split via SPM
- DB: SQLCipher + GRDB
- Keys: Keychain + Secure Enclave (when the key type allows)
- Calls: WebRTC + CallKit + PushKit
- Push: APNs background / VoIP for calls (subject to Apple policy)

### Web (internal / staging)

- React 18 + Vite
- Same protocol package as the server
- WebCrypto + @noble
- Not a substitute for mobile hardware-backed keys
- Used for development, QA, and limited desktop until a native desktop client
  exists

All three clients implement the same state machine for messages:

`draft → pending → encrypted → uploading? → sent → delivered → read`
and `failed → retrying`.

The planner (`packages/shared/src/outbox.ts`, ported to Kotlin/Swift) never
consumes a one-time prekey when a session already exists and never addresses
the sending device. Expired envelopes and completed attachment ciphertext are
deleted by a server-side TTL loop (`services/server/src/jobs/expire.ts`), not
by a public HTTP endpoint.

Local identity and session material live in an AEAD vault (`ollo-vault-v1`).
Native wraps the vault key in Keystore/Keychain (AES-256-GCM, AAD
`ollo-wrap-v1`); SQLCipher holds messages. `wipe()` on logout / revoke /
account delete. Web may wrap the vault key with a PIN via Argon2id.
Without a PIN, web localStorage is not a seizure-resistant store.

`SessionHost` (Android `MainActivity`, iOS `OlloApp`) owns `ProtocolStore`
under `noBackupFilesDir` / Application Support and `AuthRepository.connected`
(401 → refresh → wipe). iOS `OlloClient` reads access from `SessionController`
and never keeps a second copy of the refresh token. `planSessionLaunch`
restores a vault session into the inbox. Registration is blocked until a
bound libsignal engine emits `deviceRegistrationJson`. The UI never
fabricates a device payload.

## 7. Backend modules

### 7.1 Auth

- Request OTP (rate-limited, hashed storage)
- Verify OTP → issue device-bound session
- Registration lock PIN (optional, Argon2id)
- Refresh token rotation (reuse detection)
- Revoke session / revoke all
- Suspicious login signals (new device, new ASN, velocity)

### 7.2 Users

- Username allocation (normalized, unique)
- Profile (display name, about, avatar attachment id)
- Discovery by username (exact) or phone (hashed, both-parties consent)
- Block list, reports (metadata only)

### 7.3 Devices & keys

- Device registration with identity key + signed prekey + one-time prekeys
- Prekey replenishment
- Device list, rename, revoke
- Safety number material is public identity keys (not a server secret)

### 7.4 Messaging

- Accept sealed envelopes addressed to `(user, device)`
- Persist until ACK or TTL
- Fan-out to online sockets + offline mailbox + silent push
- Idempotency keys
- Delivery receipts and read receipts are themselves sealed envelopes
- Server never inspects inner content type except a coarse `envelope.kind`
  used for push collapse (`message` vs `receipt` vs `typing`)

### 7.5 Groups

- Server stores membership, roles, invite tokens (hashed), epoch
- Group name/avatar/description live in an E2EE group state message
- Sender key distribution is regular sealed envelopes
- Removing a member increments epoch; clients ratchet sender keys
- Server cannot add a silent member without clients noticing (membership
  changes are signed by an admin identity, stored on GET, applied with
  `planMembershipApply`). Invite-join is pending until that signature.
  Fan-out recipients are `planFanoutRecipients` (signed ∩ live).

### 7.6 Attachments

- Client encrypts, then requests a signed PUT URL
- Server stores object key, size, digest of **ciphertext**, TTL
- GET is authorized by a short-lived signed URL given only to the uploader
  or to a recipient who presents an envelope-issued grant
- Dedup is on ciphertext digest — identical plaintext with different keys
  does **not** collide (no plaintext confirmation oracle)

### 7.7 Calls

- Offer/answer/ICE over the existing E2EE message channel (kind=`call`)
- Optional lightweight signaling room for ICE trickle (room id is random,
  membership checked)
- TURN credentials are short-lived, per-call
- No media through the application server

### 7.8 Notifications

- Maps device → push token (token encrypted at rest)
- Sends collapse-key wakeups: `{v:1, t:"msg"}` — no sender name, no preview
  unless the user disabled the privacy default on that device
- Token rotation, invalidation

## 8. Data stores

### PostgreSQL — what and why

Transactional source of truth for identity, devices, mailboxes, groups,
abuse state. Envelopes are bytea. Partition `envelopes` by received_day.

### Redis — what and why

- Sliding rate limits
- Presence (TTL keys)
- Pub/sub to reach the node that owns a socket
- Streams for async push / mailbox drain
- Ephemeral OTP anti-replay (also stored hashed in PG)

Failure mode: Redis down → rate limits fail closed for auth, fail open for
presence (everyone looks offline), sockets still work on the local node.
Not a source of truth.

### Object storage — what and why

Ciphertext blobs. Lifecycle policy deletes after TTL. Versioning off for
user objects (nothing to restore that the user did not keep). Server-side
encryption is defense-in-depth (we already cannot read content); it protects
against casual object-store misconfiguration, not against us.

## 9. Realtime contract

- Client opens `WSS /v1/realtime` with **no token in the URL**
- First frame: `hello` with `access_token` (browser) **or** `Authorization: Bearer` on the upgrade (native), plus `resume?` and `after?`
- Server streams `envelope` frames
- Client ACKs with `ack {id}`
- Heartbeat every 25s; missed 2 → drop
- Resume: server replays un-ACKed + mailbox since cursor
- At-least-once delivery; clients de-dupe by envelope id (`rememberEnvelope`)

Messages must not be lost across: network blip, app restart, server rolling
deploy, device sleep. Durability is the PG mailbox, not the socket.

## 10. Multi-device

Each device has its own identity key and sessions.

Sending to a user = encrypting a copy for **every** of their devices
(and a copy for the sender’s other devices — self-fan-out for sync).

A new device:

1. Authenticates (OTP + optional registration lock)
2. Publishes a new identity key
3. Other devices show a “new device” warning
4. History is **not** automatically available (no plaintext on server)
5. Optional: user-initiated transfer over a QR-authenticated local channel
   or an encrypted backup key the user holds

## 11. Deployment architecture

```text
                    [CDN / static web]
                           |
[Users] --TLS 1.3--> [Ingress / NLB] --> [App Deployment (HPA)]
                                              |        |
                                         [PG primary] [Redis]
                                              |
                                         [PG replica]
[App] --presigned--> [S3]
[Clients] --TURN--> [coturn pool]
```

- Three environments: `dev` (PGlite), `staging`, `production`
- Rolling deploy, maxUnavailable 0, maxSurge 25%
- Pod disruption budgets, multi-AZ
- Secrets from the platform secret manager, never from git

## 12. SLI / SLO (configurable targets, not promises)

Defined in `services/server/src/observability/slo.ts` and Helm values.

| SLI | Staging target | Production starting target |
|---|---|---|
| API p99 (non-upload) | 250ms | 200ms |
| Envelope persist p99 | 80ms | 50ms |
| WS reconnect success < 5s | 99% | 99.5% |
| Availability (5xx excl. client) | 99.5% | 99.9% |
| Call signaling setup p95 | 2.5s | 1.5s |

These are **targets** used for alerting and capacity work, not contractual
guarantees.

## 13. Failure modes

| Failure | User impact | Mitigation |
|---|---|---|
| One app pod dies | In-flight WS drop, clients resume | HPA, PDB, resume tokens |
| One AZ dies | Brief errors | Multi-AZ, PG failover |
| PG primary dies | Write stall | Auto-failover, RPO see DR doc |
| Redis dies | Presence stale, rate-limit fail-closed on auth | Local token bucket fallback |
| S3 blip | Upload/download retry | Client resumable PUT |
| FCM/APNs down | No wakeup; mail delivered on next open | Mailbox durability |
| TURN down | Some calls fail without P2P | Multiple TURN, STUN first |
| Push provider compromise | Spurious wakes, no bodies | Sealed payloads |

## 14. What we deliberately do not store

- Message plaintext
- Attachment plaintext or filenames
- Private keys
- OTP codes after verification (hashed until expiry, then deleted)
- Push notification bodies with content
- Precise location
- Address book uploads (discovery is on-device hashing + limited match)

See SECURITY_MODEL.md and PRIVACY.md.
