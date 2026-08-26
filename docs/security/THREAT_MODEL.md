# OllO Threat Model

Method: STRIDE on components, LINDDUN on privacy. Ratings are qualitative
for a pre-audit product: L / M / H / C (critical).

Likelihood is for a motivated mid-capability attacker, not a specific APT.

## 1. Components in scope

- Mobile clients (Android, iOS), web client
- API + WebSocket modular monolith
- PostgreSQL, Redis, object storage
- FCM / APNs
- STUN / TURN
- CI/CD and build
- Operators and secret managers

Out of scope for this revision: desktop native, federated servers, SGX.

## 2. STRIDE

### 2.1 Spoofing

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| OTP brute force | M | Account takeover of unlocked accounts | 6-digit OTP, 5 tries, per-number and per-IP lockout, exponential backoff, delete OTP hash after use | SIM-swap still works without registration lock |
| OTP intercept (SS7 / SMS) | M | Same | Registration lock PIN, new-device warning, no history pull | SMS is a weak channel; lock is optional |
| Session token theft | M | Impersonate device | Device-bound refresh, rotation + reuse detection, short access TTL, TLS only | Malware on device |
| Stolen refresh reuse | M | Session hijack | Reuse → revoke family | Attacker who is first wins the race |
| Forged device identity | L | Silent extra mailbox | Identity key is client-generated; server stores public only; other devices warn on new IK | User clicks through warning |
| Push token swap | L | Wakes on wrong device | Token associated with device id + session | Spurious wakes |
| Caller ID spoof in signaling | L | Fake incoming call UI | Signaling is E2EE from a known session | Malicious contact |

### 2.2 Tampering

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| MITM TLS | L | Read/modify API | TLS 1.3, pinning on mobile, HSTS | Web PKI, pin update mistakes |
| Envelope bit flip | M | Decrypt fail / drop | AEAD tag, discard | DoS on that message |
| Malicious prekey in directory | M | Downgrade / identity mixup | Signed prekey, identity key comparison, safety number | User ignores warning |
| Group membership inject | M | Extra recipient | Signed membership (`signMembership` / prior-admin in stored JSON / `planTrustedMembers` / `planFanoutRecipients`); invite-join stays pending; clients `confirm` adds before sender-key distro | Server can still **drop** members (availability). Stolen **real** admin can sign a rogue add; other devices withhold keys until confirm |
| Malicious APK / IPA | L | Full compromise | Store signatures, reproducible builds goal, Play Integrity optional | Sideload, supply chain |
| DB row rewrite | M | Drop/duplicate mail, fake profile | App-level AEAD on mail; profiles are public by nature | Metadata integrity |

### 2.3 Repudiation

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| User denies sending | H | Social | Messages are not globally signed for non-repudiation on purpose (deniability is a feature of Signal-style protocols) | N/A — deniability is intended |
| Operator denies reading metadata | M | Insider | Admin audit log (who queried what account), no plaintext to read | Collusion, log deletion — ship logs off-box |

### 2.4 Information disclosure

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| Server reads mail | M (if we designed badly) | Catastrophic | No keys on server, AEAD, tests that scan logs/DB for plaintext fixtures | Bugs in client sealing |
| DB leak | M | Metadata + ciphertext | Encryption at rest (platform), peppered phones, TTL | Graph, sizes, times |
| Object store leak | M | Ciphertext blobs | Per-file keys in envelopes | Size/timing |
| Log leak of OTP / token | M | ATO | Redacting logger, denylist of field names, tests | Mis-instrumentation |
| Push body leak | L | Preview on lock screen / Google | Empty bodies by default | User disables privacy |
| Thumbnail / screenshot / app switcher | H | Shoulder surf, OS cache | FLAG_SECURE / screenshot policy, hide switcher, no plaintext thumbnails on disk | OS bugs |
| Clipboard linger | H | Paste leak | Clear after timeout, avoid copy of secrets | User copies a message |
| Backup leakage (Android Auto, iCloud) | M | Key / DB extract | Exclude DB from plaintext backup; Keystore/Keychain flags | User enables insecure backup |
| Traffic analysis | H | Who talks to whom | TLS, padding buckets, no extra headers | Network adversary still sees IPs and timing |
| Username enumeration | H | Account existence | Uniform error timing, rate limit; usernames are inherently public if known | Username is a public handle |
| Phone enumeration | M | Probe if number is on OllO | Constant-time-ish responses, rate limit, hashed storage, CAPTCHA on velocity | Determined online guessing |

### 2.5 Denial of service

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| OTP flood / SMS bill | H | Cost, lockout | Per-IP, per-number, per-device quotas, provider-level caps | Distributed botnet |
| Envelope flood | H | Mailbox / disk | Per-sender quotas, max envelope size, group fan-out budget | Popular groups |
| WS connection flood | H | File descriptors | Edge limits, auth-before-upgrade, per-account connection cap | Large botnet |
| Huge attachment | M | Cost | Max size, auth, prepaid quota | Paid attacker |
| TURN abuse (relay as VPN) | M | Bandwidth bill | Per-call credentials, bandwidth cap, time cap | Determined abuse |
| Slowloris / HTTP | M | Workers stuck | Timeouts, ingress limits | — |
| Poison prekey store | L | Recipients cannot start session | Replenish, signed prekeys, monitoring of prekey depth | Temporary unavailability |

### 2.6 Elevation of privilege

| Attack | L | Impact | Mitigation | Residual |
|---|---|---|---|---|
| Authz skip (IDOR) | M | Read others’ mailbox / devices | Every query scoped by authenticated device; tests | Missed endpoint |
| Admin panel exposed | L | Full metadata | No public admin UI in v1; break-glass via audited kubectl | Human process |
| Path traversal on objects | L | Cross-object read | Random object keys, signed URLs, no user path | — |
| SSRF via attachment URL | L | Cloud metadata | We never fetch user-supplied URLs; clients upload to us | — |
| Deserialization gadget | L | RCE | JSON only, no pickle/yaml, schema validation | Parser bugs |

## 3. LINDDUN (privacy)

| Category | Issue | Mitigation |
|---|---|---|
| Linkability | Same user id across devices and groups | Separate from display; no global advertising id; minimize logs |
| Identifiability | Phone number at registration | Peppered HMAC; no other PII required |
| Non-repudiation | Delivery logs | Short TTL on envelopes and connection logs |
| Detectability | Online status | Coarse, optional, not exposed to non-contacts |
| Disclosure of information | Profile | User-controlled; username search is exact-match |
| Unawareness | Users not knowing metadata exists | PRIVACY.md, in-app security primer |
| Non-compliance | Retention too long | TTL jobs, documented periods, no analytics warehouse in v1 |

## 4. Special scenarios demanded by the product brief

### MITM
TLS + pin. Sealed envelopes still useless to MITM even if TLS dies (they
can drop or delay). Residual: first-launch pin trust, web.

### Replay
Envelope ids are UUIDv7; devices keep a bounded replay cache (4096 ids,
vault slot `replay.v1`, omitted from backups). OTP is single-use.
Refresh tokens rotate. Call signaling nonces. Residual: after eviction a
hostile mailbox can re-deliver an old envelope.

### Credential / token theft
See spoofing. Tokens never in logs, never in push, never in URLs.

### Device compromise / stolen phone
See SECURITY_MODEL §6.7–6.9.

### Rooted / jailbroken
Warn, optional restriction of safety-number-verified chats. Cannot enforce.

### Malicious app on the same phone
Android: scoped storage, no exported providers with mail. iOS: sandbox.
Residual: accessibility malware, notification listener (we hide previews).

### Malicious server administrator
Can see metadata, can DoS, cannot read mail. Admin actions audited.

### Database / object leak
Ciphertext + metadata. Peppers and SQLCipher keys are not in the DB dump
if secret manager holds.

### Compromised push / TURN / DNS
See SECURITY_MODEL §6.4–6.6.

### Malicious insider + supply chain + dependency
Pinned deps, CI scans, signed images, two-person review on crypto and auth
paths. Residual: sophisticated build-system attack.

### Reverse engineering
Assume the client is public. Secrets are not in the binary. Safety is in
the protocol, not obfuscation. R8/ProGuard for Android is for size, not
security theater.

### Traffic analysis / metadata
Reduced, not eliminated. Padding + TTL + no content in push.

### Account takeover / SIM swap / social engineering
Registration lock, new-device warnings, remote revoke, support must never
ask for OTP or PIN (runbook). Residual: user gives PIN to an impostor.

## 5. Abuse without breaking E2EE

We do **not** build a central plaintext scanner.

What we do instead:

- Rate limits and velocity checks
- User reports that include **reporter, reportee, envelope ids, optional
  user-attached screenshot** (the screenshot is the reporter’s choice and
  is a plaintext they already have)
- Graph features (fan-out degree, new-account burst)
- Optional phone reputation at registration (third party sees a number, not
  mail)

This is enough to fight spam without a mass-decryption backdoor.

## 6. Residual risk register (top)

1. SMS OTP + no registration lock → SIM-swap ATO of a new device.
2. TypeScript protocol path not independently audited.
3. Metadata graph on the server.
4. Web client key storage weaker than Keystore / Secure Enclave.
5. User ignoring new-device / safety-number change warnings.
6. Supply-chain compromise of a crypto dependency.
7. TURN without media E2EE on a fallback path.
8. Operator error enabling `OTP_DEV_REVEAL` or debug routes in prod.

Each item has an owner in OPERATIONS.md and a test or control in CI.
