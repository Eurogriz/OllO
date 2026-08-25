# OllO Cryptography

**Rule: we do not invent primitives. We do not invent a “sort of Signal”
protocol. We implement published specifications with audited libraries.**

This document is required reading before touching `packages/crypto`.

## 1. Libraries

| Library | Role | Why it is acceptable |
|---|---|---|
| `@noble/curves` (audited, Paul Miller) | X25519, Ed25519 | Independently audited, constant-time, no native code |
| `@noble/ciphers` | XChaCha20-Poly1305, HKDF-SHA256 via `@noble/hashes` | Same |
| `@noble/hashes` | SHA-256, HMAC, HKDF, BLAKE2 | Same |
| `@noble/post-quantum` (optional future) | ML-KEM hybrid | Not enabled in v1 |
| `libsodium` / `libsodium-wrappers` | Backup AEAD / random | Reference C implementation, widely audited |
| Official **libsignal** (Android / iOS production) | X3DH + Double Ratchet + Sender Keys | The implementation we want on shipped native apps |

Web / Node path in this repository implements the **published Signal
specifications** on top of `@noble`:

- X3DH: https://signal.org/docs/specifications/x3dh/
- Double Ratchet: https://signal.org/docs/specifications/doubleratchet/
- Sender Keys: https://signal.org/docs/specifications/group/#sender-keys

That TypeScript path exists so the server integration tests and the web
client can run without native bindings. **It is not a substitute for
libsignal on production mobile builds** and must be independently reviewed
before any web production launch.

Android: `org.signal:libsignal-client`
iOS: Swift package `libsignal-client`

The `CryptoEngine` interface (`packages/crypto`) is the only thing the apps
talk to. Swapping the engine does not change envelope format.

## 2. Primitives

| Purpose | Primitive | Parameters |
|---|---|---|
| Identity DH | X25519 | 32-byte keys |
| Identity signatures | Ed25519 | 32-byte keys |
| AEAD | XChaCha20-Poly1305 | 24-byte nonce, 16-byte tag |
| KDF | HKDF-SHA-256 | info-bound per use |
| Hash | SHA-256 | safety numbers, digests |
| Password / PIN / registration lock | Argon2id | m=19 MiB, t=2, p=1 (OWASP) |
| Native wrap (SQLCipher / identity) | AES-256-GCM | 12-byte IV, AAD `ollo-wrap-v1`, key in Keystore / Keychain |
| Phone at rest | HMAC-SHA-256(pepper, e164) | pepper in secret manager |
| Local DB | SQLCipher AES-256-CBC / HMAC (library default) | key in Keystore/Keychain |
| Random | `crypto.getRandomValues` / `SecureRandom` / `SecRandomCopyBytes` | never Math.random |

Nonce uniqueness: 24-byte random nonce per AEAD invocation. No counters that
could repeat across processes.

## 3. Keys — inventory

| Key | Created | Stored | Rotated | Destroyed |
|---|---|---|---|---|
| Device identity X25519 | Device registration | Keystore / Keychain / web: wrapped in local DB key | Never (change = new device) | Device revoke / app uninstall / remote wipe |
| Device identity Ed25519 | Same | Same | Same | Same |
| Signed prekey | Registration + every ~7d | Public on server; private on device | 7 days, keep previous 2 | After grace |
| One-time prekeys | Batches of 100 | Public on server; private on device | Consumed once | After use or stale |
| Root / chain / message keys | X3DH + ratchet | Encrypted local DB only | Every message (message key) | After decrypt + skip-key window |
| Attachment key | Per file, 32 random bytes | Inside E2EE message, not on server | N/A | With message delete |
| Local DB key | First launch | Android Keystore / iOS Keychain | Rare (rekey) | Uninstall |
| Registration lock | User | Argon2id hash on server | User | User |
| Native DB wrap key | First launch | Android Keystore / iOS Keychain (this-device, when-unlocked) | Rare | Wipe / uninstall |
| Session access / refresh | Login | Memory + Keychain (refresh) | Access 15m; refresh rotate | Logout / reuse detected |

Server holds **only public** identity / prekeys.

## 4. X3DH (initial agreement)

Alice wants to talk to Bob’s device D.

She fetches from the key server:

- `IK_b` identity DH public
- `SPK_b` signed prekey + Ed25519 signature over it
- `OPK_b` one-time prekey if any remain

She verifies the signature with Bob’s identity Ed25519 key.

She generates ephemeral `EK_a` and computes the standard X3DH shared secret:

```
DH1 = DH(IK_a, SPK_b)
DH2 = DH(EK_a, IK_b)
DH3 = DH(EK_a, SPK_b)
DH4 = DH(EK_a, OPK_b)          # omitted if no OPK
SK  = HKDF(DH1 || DH2 || DH3 || DH4, salt=0, info="ollo-x3dh-v1")
```

She sends a prekey envelope containing `IK_a`, `EK_a`, the used prekey ids,
and the first ratchet message. The server cannot compute SK.

## 5. Double Ratchet

After X3DH, Alice and Bob run the Double Ratchet as specified:

- DH ratchet on every received new ratchet public key
- Symmetric ratchet per message
- Header: ratchet public key, previous chain length (`pn`), message number (`n`)
- Header can be sent in the clear inside our outer transport envelope
  (it is not content); we still wrap the whole inner message in the
  transport TLS + our envelope container
- Skipped message keys kept up to `MAX_SKIP=256` then dropped (DoS bound)
- AEAD associated data = `IK_a || IK_b || header` so identity mixup fails

Forward secrecy: old message keys are deleted after use.
Post-compromise security: DH ratchet heals after a subsequent round-trip.

## 6. Groups — Sender Keys

We do **not** invent a group ratchet.

Each member, per group, per device, holds a Sender Key:

- A chain key, an index, and an Ed25519 signing key for that sender chain
- Distributed to each other member device via the existing 1:1 sessions,
  signed by the sender’s long-term identity Ed25519 key
- Message: XChaCha20-Poly1305 under `HKDF(chain_key, i)`, plus an Ed25519
  signature over `nonce || ciphertext || aad` so other members who know the
  chain key still cannot forge as that sender
- On member **remove** or device revoke: increment group epoch, all members
  generate fresh sender keys and redistribute
- On member **add**: current members send them the current sender keys over
  1:1 (they cannot read history before the add unless someone forwards it)
- Server copies the **same** opaque ciphertext to every other member device
  (`POST /v1/groups/:id/fanout`). It cannot derive sender keys.

Server role: membership + epoch + fan-out of opaque ciphertext.
Server cannot derive sender keys.

Evolution path (not in v1 code): IETF MLS (RFC 9420) via OpenMLS. The
envelope `alg` field is versioned so we can migrate.

## 7. Attachments

```
key  = random(32)
nonce = random(24)
ct   = XChaCha20-Poly1305_Encrypt(key, nonce, file_bytes, aad=filename||mime)
digest = SHA-256(ct)
upload ct to object store
send {object_id, nonce, key, digest, size, mime, filename} inside E2EE message
```

Server sees `object_id`, `size`, `digest(ct)`, never `key` / `filename`.

Thumbnails and waveform previews are encrypted the same way with a separate
key also carried in the envelope. The server never generates previews.

Resumable upload is of **ciphertext** (chunked, content-range). Integrity is
the digest check on the receiver.

Dedup: only if two ciphertexts are byte-identical (same key, same file).
We do **not** hash plaintext on the server. No confirmation oracle.

## 8. Safety number

```
safety_number = fingerprint(sort(IK_a_pub, IK_b_pub))
```

Displayed as 60 decimal digits in 12 groups (Signal-style) and as a QR
payload `ollo:safety:v1:<hex>`.

A change of either identity key is a hard warning. Users must re-verify.

Device-list hash is shown under “devices” so a silent extra device is
visible even if the primary identity is unchanged.

## 8b. Encrypted backup

```
salt = random(16)
key  = Argon2id(passphrase, salt, t=2, m=19MiB, p=1, dkLen=32)
blob = XChaCha20-Poly1305_Encrypt(key, account_export, aad="ollo-backup-v1")
```

`account_export` is identity + sessions + sender keys + local history.
Access / refresh tokens are **not** included. The server stores only `blob`.

A wrong passphrase or a flipped ciphertext bit fails closed.

## 8c. Local-at-rest vault

```
vault_key = random(32)                         # or unwrap(PIN) via Argon2id
blob      = XChaCha20-Poly1305_Encrypt(vault_key, account_json, aad="ollo-vault-v1")
```

Web stores `blob` in `localStorage`. The vault key is either:

- wrapped with the same Argon2id backup KDF under a user PIN, or
- stored beside the blob (protects casual grepping, **not** device seizure).

Native clients wrap `vault_key` in Android Keystore / iOS Keychain (StrongBox /
Secure Enclave when present) and keep history in SQLCipher. Web is not a
substitute for hardware-backed wrap.

A wrong key or a flipped ciphertext bit fails closed. Access / refresh tokens
inside the vault are still session secrets — a stolen unlocked origin dump
yields them. PIN wrap raises the bar for a seized disk, not for XSS.

## 9. Sealed push and call signaling

Push payload (production):

```json
{"v":1,"t":"msg"}
```

No sender, no preview, no envelope. The client wakes, connects, pulls.

Call signaling (offer, answer, ICE, hangup) is an E2EE message with
`inner.type = call`. The optional signaling room only maps a random
`call_id` to the already-authenticated devices.

Media: WebRTC DTLS-SRTP for the transport. An SFrame key is agreed inside
the E2EE `call_signal` so a future insertable-stream transform (reviewed
library, not a homemade RTP cipher) can hide media from the TURN relay.
Until that transform is enabled, a compromised TURN still sees DTLS-SRTP
ciphertext, not the signaling SDP (SDP never leaves the E2EE envelope).

## 10. What we will never do

- Roll our own block cipher, hash, or RNG
- Use ECB, unauthenticated AES-CBC, or RSA PKCS#1 v1.5
- Use `Math.random` for keys
- Derive keys from usernames
- Put private keys in `SharedPreferences` / `UserDefaults` / `localStorage`
  without a wrapping key from the platform store
- Log keys, nonces-with-keys, OTP, or plaintext
- Provide a server-side “compliance decrypt” API

## 11. Test obligations

`packages/crypto` must keep:

- X3DH known-answer tests
- Double Ratchet skipped-message and reorder tests
- Sender-key epoch rotation tests
- Attachment round-trip + tamper tests
- Safety-number stability tests
- A scanner test that fails if a fixture plaintext appears in a fake server log

Native apps additionally run libsignal interop tests against the published
test vectors before a release that claims protocol compatibility.

## 12. Review status

| Component | Status |
|---|---|
| Primitive choice | Standard, pre-audit |
| TypeScript X3DH / DR / Sender Keys | Implementation of public spec, **needs independent review** |
| libsignal on Android / iOS | Intended production engine, audited upstream |
| Envelope format | Specified in `packages/protocol` |
| Production claim “as safe as Signal” | **Forbidden** until reviews land |
