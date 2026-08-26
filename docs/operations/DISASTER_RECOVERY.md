# Disaster Recovery

## Objectives (starting targets, configurable)

| Environment | RPO | RTO |
|---|---|---|
| staging | 24h | 8h |
| production | 15 minutes (WAL) | 1 hour |

RPO/RTO are **targets**. They are not a guarantee until a restore has been
rehearsed and timed.

## What is backed up

| Store | Method | Period |
|---|---|---|
| PostgreSQL | Continuous WAL + daily snapshot | PITR 7 days, snapshots 14 days |
| Object store | S3 cross-AZ (platform) + lifecycle | Ciphertext only |
| Secrets | Secret manager replication | Platform default |
| Redis | **Not** a source of truth — no backup | Rebuild empty |

Not backed up (by design): message plaintext (we never had it), local
device databases (user’s device).

## What a restore cannot bring back

- Messages already ACKed and deleted from the mailbox
- Attachment objects past TTL
- A user’s local history if they lost all devices and had no backup

## Procedure — Postgres

1. Declare incident, freeze deploys.
2. If primary is corrupt: promote replica (`RTO` path).
3. If logical corruption (bad migration): PITR to before the event.
4. Run `npm run migrate` only if the restored schema is behind.
5. Verify `/readyz`, envelope send smoke, auth smoke.
6. Invalidate refresh tokens if the dump may have leaked (`logout-all`
   global flag).

Rehearse quarterly. The rehearsal date is recorded in the ops log.

## Procedure — region loss

Terraform can stand up a second region. DNS cutover. Object store
replication must have been enabled **before** the event (it is not in the
default staging config).

## Procedure — secret leak

Rotate: session signing key (all users re-auth), phone pepper (dual-pepper
window: write new, read both, then drop old), OTP pepper, S3 keys, TURN
secret, push keys. Documented in `services/server/src/security/rotation.ts`.

## Procedure — ransomware / stolen snapshot

Assume metadata disclosure. Notify. Rotate secrets. We still cannot decrypt
user mail — that statement must be reviewed by counsel before being used
externally.
