# Chaos catalog

These experiments are **not executed** in this repository. Run them
against staging with an on-call and a rollback.

## 1. Datastore

- Kill the primary Postgres for 30s. API must return 5xx, not leak
  envelopes. Clients retry outbox.
- Restore a 15-minute-old snapshot. Sessions issued after the snapshot
  must fail refresh (family reuse). Clients wipe.
- Drop `account_ed25519` rows. OTP must not re-attach devices without
  `register-key`.

## 2. Redis

- Partition Redis. Rate limits fail closed when `REDIS_REQUIRED=true`.
- Fill Redis to `maxmemory`. Presence may go stale; auth must not
  disable OTP caps by falling back to unbounded memory.

## 3. Object store

- Make S3 return 503 on PUT. Attachment upload fails; no plaintext
  filename is logged.
- Delete a ciphertext object. Download 404s; the envelope still
  decrypts the pointer and the client shows a missing file.

## 4. SMS

- Twilio 5xx. `request-otp` still creates a challenge (or fails
  closed — pick one and test it). OTP is never logged.
- Deliver the OTP to the attacker. They still cannot add a device to
  an already-keyed account.

## 5. TURN

- Expire REST-HMAC credentials. New ICE fails; in-call DTLS continues
  until ICE restart.
- Capture TURN. Observer sees DTLS-SRTP, not SDP (SDP is E2EE).

## 6. Process

- SIGKILL one API replica during envelope fan-out. At-least-once
  delivery; clients de-dupe by envelope id.
- Rotate `SESSION_SIGNING_KEY`. Old access tokens 401; refresh still
  works if the hash pepper is unchanged.

## Pass / fail

A chaos run that leaks plaintext, OTP, or private keys is a release
blocker. A run that is not performed is **not** a pass.
