# Audit readiness

This is a **checklist**, not a pass. OllO must not claim Signal-level
security until an independent party completes every item below and
signs a written report.

## Not done here

- Independent application pentest
- Independent mobile pentest
- Independent cryptographic review of the TypeScript X3DH / Double
  Ratchet / Sender Keys path
- libsignal interop tests compiled against Android SDK / Xcode
- Production load / chaos executed against staging
- Formal threat-model review with the operator

A green CI in this repository is **not** an audit.

## Ready for an auditor

| Area | Artifact |
|---|---|
| Protocol | `docs/security/CRYPTOGRAPHY.md`, `packages/protocol` |
| Account vs device keys | `planOtpAccountBind`, `AccountKey` (Tink / CryptoKit), `register-key` |
| Native engine | `LibsignalEngine` + official `libsignal-client:0.58.1` |
| Fail-closed default | `UnboundCryptoEngine` is still `SessionHost` default |
| OTP | First OTP requires dedicated `account_ed25519`; 2nd device is `register-key` |
| Compact link | `sealLinkCompact` + QR v6-L only (136 data cw, 1 RS block) |
| SMS / S3 / Redis | Adapters in `sms.ts`, `s3.ts`, `redis.ts`; prod config refuses `none` |
| Tests | `packages/crypto`, `packages/shared`, `services/server` integration |
| Pentest catalog | `tests/security/plan.md` |
| Chaos catalog | `tests/security/chaos.md` |
| Load catalog | `tests/load/k6-messages.js` |

## Forbidden claims

- “As safe as Signal”
- “Audited” without naming the firm, date, and scope
- “libsignal on web” (web still uses the TypeScript engine)
- “Native and web sessions interoperate” (XEdDSA / wire format differ)

## Operator must still provide

- Production Twilio (or equivalent) credentials
- Redis + S3 + TURN secrets from a secret manager
- Staging environment for the pentest
- Signed release builds (this image has no Android SDK / no macOS)
