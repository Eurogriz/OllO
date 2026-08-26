# OllO Security Model

This document is the source of truth for **what is protected, against whom,
and what remains visible**. It is intentionally conservative.

OllO does **not** claim Signal-level security, perfect forward secrecy in
every edge case, or anonymity. Claims of that strength require an independent
security audit, a cryptographic review, and operational evidence.

## 1. Assets

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Message plaintext | Critical | Sender and recipient devices only |
| Attachment plaintext | Critical | Same |
| Call media | Critical | Endpoints (+ TURN as ciphertext if E2EE media on) |
| Identity private keys | Critical | Device secure storage |
| Session / ratchet state | Critical | Encrypted local DB |
| Registration lock PIN | High | Argon2id hash on server; PIN on device |
| Phone number | High | Optional HMAC if OTP path is used; not the account identifier |
| Social graph (who talks to whom) | High | Partially visible to server |
| Profile display name / avatar | Medium | Server-visible by design (discovery) |
| Push tokens | Medium | Encrypted at rest |
| Device list | Medium | Server |

## 2. Adversaries

1. **Network attacker** — on-path, Wi-Fi, ISP, nation-state on the wire.
2. **Malicious or compromised server operator** — full DB + object store + logs.
3. **Stolen database / object bucket** — offline dump.
4. **Compromised push provider** (FCM / APNs).
5. **Compromised TURN server**.
6. **Thief with a locked phone**.
7. **Thief with an unlocked phone**.
8. **Malware / rooted / jailbroken device**.
9. **Malicious contact** (other endpoint).
10. **Curious insider** with production access.

## 3. What the server CAN see

Even a fully honest server necessarily sees:

- That an account exists, its user id, username, and profile fields the user
  chose to publish.
- The account Ed25519 public key (the address). Optional keyed hash of a phone if the legacy OTP path is used.
- Device identifiers and **public** identity / signed-prekey material of live
  devices. Consumed one-time prekeys keep only a `key_id` tombstone. Revoked
  devices have their directory bytes wiped.
- That device A sent an envelope of size N at time T to device B
  (row is deleted on ACK or TTL; revoke empties that device's mailbox
  and drafts).
- Group membership and roles (required for fan-out).
- Ciphertext attachment sizes and ciphertext digests.
- Coarse envelope kind (`message` / `receipt` / `typing` / `call`) so we can
  collapse push and avoid waking the device for receipts if desired.
- IP addresses and TLS metadata on the edge (retention minimized).
- Abuse-control counters (rate, reports).

This is **metadata**. It is enough to reconstruct a social graph and traffic
pattern. We reduce it; we do not pretend it is absent.

## 4. What the server CANNOT see

If clients are uncompromised and the protocol is implemented as specified:

- Message bodies
- Attachment bytes, filenames, MIME of the inner file
- Voice-message audio
- Call media (when insertable-stream / SFrame E2EE is active)
- Ratchet keys, identity private keys, attachment keys
- Safety number (it is a hash of public keys the server already has, but the
  server is not in the verification ceremony)
- Local drafts, local search index, local contacts list

A stolen database therefore yields **ciphertext + metadata**, not mail.

## 5. Inevitable metadata

| Metadata | Why inevitable | Mitigation |
|---|---|---|
| Sender → recipient at time T | Routing | Drop after delivery + TTL; no long-term analytics warehouse |
| Envelope size | Transport | Padding buckets on the client (256/512/1k/4k/16k/64k) |
| Group membership | Fan-out | Signed membership list; prior-admin in stored JSON; no silent adds |
| Online/approximate last-active | Socket / push | Coarse last-active (day); not returned to non-contacts |
| IP at connection | TCP | Short retention, no sale, no enrichment beyond abuse |
| Account public key | Routing / discovery | Public by design; private key stays on device |

## 6. Compromise scenarios

### 6.1 Compromised server (running process + DB + objects)

Attacker can:

- Deny service, drop or delay mail, add fake devices **if they also steal
  a valid session** (they cannot forge a device identity key).
- Inject a new device into the account **only** by proving the account Ed25519 key (and lock, if set).
  Existing devices will show a new-device warning because the identity key
  is new.
- Read all metadata listed in §3.
- Replace the API binary to serve a malicious client update — **supply chain
  / update integrity is out of band** (Play / App Store signatures, and
  pinable update manifests for sideload).

Attacker cannot:

- Decrypt historical envelopes (no keys).
- Decrypt attachments (key is inside the envelope).
- Silently read future mail without a malicious client or a new device that
  the user accepts.

Residual risk: a malicious update or a compromised build pipeline.

### 6.2 Stolen database dump (offline)

Yields public keys, phone HMACs (brute-forceable if pepper also leaked and
the number space is small), ciphertext envelopes, group membership.

Without `PHONE_HMAC_PEPPER` the phone column is not reversible.
If the pepper leaks too, phone numbers are enumerable offline — treat pepper
like a master secret.

### 6.3 Stolen object bucket

Ciphertext blobs. Useless without attachment keys from envelopes + client
ratchet state.

### 6.4 Compromised push provider

Can send arbitrary wakes, measure when we notify, perhaps correlate tokens
to Google/Apple accounts. Cannot read message bodies (we do not send them).
Cannot decrypt envelopes.

### 6.5 Compromised TURN

Sees client IPs and media packets. With SFrame/Insertable Streams the media
payload is E2EE; packet timing and sizes remain. Without E2EE media, a TURN
operator can listen — this is why E2EE media is the default.

### 6.6 Compromised DNS / MITM

TLS 1.3 + certificate pinning on mobile clients (pins in the app, backup
pins). Web relies on CT + browser PKI. A broken pin update is an operational
hazard; pins are rotated with a staged backup pin.

### 6.7 Stolen locked phone

Hardware-backed keys + SQLCipher key in Keystore/Keychain, requiring
biometric/passcode. Attacker gets the sealed blob. Residual: weak device
passcode, old Android without StrongBox, unpatched lock-screen bugs.

### 6.8 Stolen unlocked phone / session

Attacker is the user. They can read chats, send as the user, accept new
devices. Mitigations: screen lock timeout, locally encrypted backups off by
default, remote device revoke from another device (access of the revoked
device fails closed on the next request; live sockets are dropped),
disappearing messages.

### 6.9 Rooted Android / jailbroken iOS / malware

Security model **collapses** for that device. We can detect some signals and
warn, we cannot win against a kernel-level attacker. Play Integrity / DeviceCheck
are optional signals, never the only control (they also hurt privacy and
sideloading).

### 6.10 New device

No history from the server. Other devices warn. Adding a device requires
the same identity private key (or a restored backup of it). Registration
lock PIN (if set) is required in addition.

### 6.11 Lost device / no backup

The account address is the first-device Ed25519 public key. If that
private key is lost and there is no encrypted backup, the account cannot
be recovered. A new keypair is a new account. Phone/SIM swap does not
take over a key-rooted account.

### 6.12 Compromised client contact

They can screenshot, forward, record calls. Disappearing messages reduce
retention, they do not stop a hostile endpoint. This is unsolvable without
DRM fantasies we will not build.

## 7. Key hierarchy (summary)

```text
identity_key (X25519 + Ed25519)     — long-term, per device
  signed_prekey                     — rotated ~7 days
    one_time_prekeys                — consumed, replenished
      x3dh → root_key
        double_ratchet
          chain_key → message_key (AEAD)
attachment_key                      — random per file, wrapped in message
local_db_key                        — platform keystore
```

Full lifecycle: CRYPTOGRAPHY.md.

## 8. Multi-device security

- Each device is a separate cryptographic identity.
- Sending: N independent sealings, one per recipient device + other own devices.
- Revocation: server stops fan-out; remaining devices drop sessions to the
  revoked identity and show a warning if it reappears.
- Verification: safety number is `H(sort(IK_a, IK_b))` over the **primary**
  identities, plus a device list hash so extra devices cannot hide.

## 9. Update and supply chain

- Dependencies pinned; lockfile committed.
- CI: SAST, secret scan, npm audit / osv-scanner, image scan.
- Production images signed (cosign).
- No unsigned native crypto code from random gists.
- Mobile release signing keys live in the org’s HSM / Play App Signing /
  Apple, never in git.

## 10. Explicit non-promises

- We do not promise protection against a global passive adversary correlating
  packet times across the whole network.
- We do not promise that a hostile group member cannot leak content.
- We do not promise that disappearing messages are gone from a backup the
  user made.
- We do not promise that web clients are as strong as hardware-backed mobile.
- We do not promise “military grade” anything.
- Preview/development may allow iframe embedding from `*.e2b.app` and
  `*.arena.ai` so the hosted preview can load. Production must keep
  `X-Frame-Options: DENY` and `frame-ancestors 'none'`.

## 11. Before production

Mandatory:

1. Independent application security audit.
2. Independent cryptographic review of the TypeScript protocol path **or**
   exclusive use of official libsignal on all shipped clients.
3. Penetration test of API, mobile, infra.
4. Abuse / SIM-swap tabletop.
5. Restore test of backups.
6. Threat-model sign-off on leftover `OTP_DEV_REVEAL` and similar flags
   (must be impossible to enable in the production image).
