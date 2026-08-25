# Operations

## SLI / SLO

Targets live in Helm values and `slo.ts`. They are **targets**, not promises.

| SLI | Prod target | Alert |
|---|---|---|
| Availability (non-4xx) | 99.9% / 30d | < 99.5% / 1h |
| API p99 | 200ms | > 500ms / 15m |
| Envelope persist p99 | 50ms | > 200ms / 15m |
| WS reconnect < 5s | 99.5% | < 97% / 15m |
| Error rate 5xx | < 0.1% | > 1% / 5m |
| Mailbox depth p99 | < 1000 | > 10k |
| Prekey depth min | > 10 / device | = 0 for > 1% devices |

## Metrics (no PII)

- `ollo_http_requests_total{route,code}`
- `ollo_http_request_duration_seconds`
- `ollo_ws_connections`
- `ollo_envelopes_accepted_total`
- `ollo_envelopes_delivered_total`
- `ollo_envelopes_mailbox_size`
- `ollo_otp_requested_total` / `ollo_otp_failed_total` (no phone labels)
- `ollo_attachment_bytes_total`
- `ollo_calls_started_total`

Forbidden labels: user id, phone, username, IP.

## Logs

JSON, `request_id`, `device_id` (not user phone), level, message.

Redacted always: `otp`, `token`, `authorization`, `password`, `pin`,
`refresh`, `ciphertext` (logged as byte length only), `key`, `secret`.

## Traces

OpenTelemetry, 1–5% sample in prod. Span names are route templates, never
raw URLs with ids if we can avoid it.

## On-call starter runbooks

**API 5xx spike.** Check `/readyz`, PG connections, last deploy. Rollback
via Helm revision. Envelopes are in PG — safe.

**WS mass disconnect.** Usually deploy or LB idle timeout. Clients resume.
If not, check sticky vs. resume path (resume does not need stickiness).

**OTP failures.** SMS provider, rate-limit false positive, clock skew.
Do not “just disable rate limits”.

**Mailbox growth.** Consumer lag or client bug. Drain is `GET /v1/envelopes`.
TTL job deletes after 30 days.

**Push dead.** FCM/APNs credentials, token invalidation. Mail still waits.

**TURN high bytes.** Credential leak used as a VPN. Rotate `TURN_SECRET`,
tighten per-call caps.

## Access

No standing production kubectl for humans. Break-glass via audited IAM
with 1-hour tokens. No SQL as superuser from laptops against prod.
