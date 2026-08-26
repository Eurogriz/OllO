# Testing

## Layers

| Layer | Where | Must cover |
|---|---|---|
| Unit | `packages/*/src/**/*.test.ts`, Android/iOS test targets | Crypto, validators, state machines |
| Integration | `services/server/src/**/*.test.ts` | Auth, mailbox, groups, grants |
| API | `tests/api` | OpenAPI conformance |
| E2E | `tests/e2e` | Two users, send/receive, group, attachment |
| Crypto | `packages/crypto` | X3DH, ratchet, sender keys, tamper |
| Concurrency | server tests | Double-ack, prekey race, refresh reuse |
| Load | `tests/load` | k6 scripts |
| Security | `tests/security` | No plaintext in logs/DB, pin headers, IDOR |
| Chaos | `tests/chaos` | Kill WS mid-send, PG retry |

## Critical paths (definition of done)

A change that touches any of these is incomplete without tests:

- Encryption / decryption
- Key exchange and prekey consumption
- Sealed session directory (`planKeyFetch`, identity-change, wipe)
- Durable protocol store (prekeys, file restart, local TTL history)
- Device roster hash, OPK peek without consume, refresh-reuse wipe
- Session launch (`planSessionLaunch`, vault restore, wipe → need-auth)
- Unbound `deviceRegistrationJson` fails closed before OTP
- iOS `AuthRepository` 401-refresh-wipe and incomplete device JSON rejection
- Device registration and revoke
- Group membership + epoch
- Invite-join stays pending; fan-out skips unsigned extras
- Prior-admin on stored signed JSON; SQL role upgrade cannot sign
- Membership `confirm` on add; sender keys wait for `confirmPendingMembership`
- Message ordering and de-dupe
- Attachment encrypt / digest / grant
- Reconnect / resume
- Multi-device fan-out
- Call signaling
- OTP rate limit and registration lock

## Coverage

Aim: high on `packages/crypto`, `modules/auth`, `modules/messaging`,
`modules/keys`. We do not chase 100% of UI chrome.

## Security tests before production

- Independent pentest (API, mobile, infra)
- Cryptographic review of the TS engine **or** libsignal-only ship
- Dependency / supply-chain review
- Binary / reverse-engineering assessment of mobile releases

See `tests/security/plan.md`.
