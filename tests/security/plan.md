# Security test plan

Mandatory before any production launch. OllO must not claim Signal-level
security until these are done by an independent party.

## 1. Application pentest

- Auth: OTP brute, refresh reuse, session fixation, IDOR on envelopes,
  devices, attachments, groups
- Injection: SQL, header, path traversal on object keys
- SSRF: attachment URLs (we must never fetch user URLs)
- WS: unauthenticated upgrade, cross-user push
- Rate limits: OTP, login, envelope flood

## 2. Mobile pentest

- Keystore / Keychain flags
- Backup leakage
- Screenshot / recents
- Notification extras
- Certificate pinning bypass attempt
- Exported components
- WebView (should be absent)

## 3. Cryptographic review

- TypeScript X3DH / Double Ratchet / Sender Keys vs published spec
- Or: prove production clients use only official libsignal
- Attachment key wrapping
- Safety number stability
- Replay / reorder / skip-window
- Group epoch after remove

## 4. Infra review

- Secret manager, no secrets in images
- Network policies
- RDS / S3 / Redis access
- TURN credential scope
- Log redaction sample from staging

## 5. Supply chain

- Lockfile integrity
- Image signing
- Dependency advisories
- Build reproducibility

## 6. Pass / fail

A critical finding in auth, crypto, or plaintext leakage is a release blocker.
