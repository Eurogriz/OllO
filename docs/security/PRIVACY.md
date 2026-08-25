# OllO Privacy

Language of the product UI: Russian and English. This document is the
operator-facing privacy specification.

## What we collect

| Data | Purpose | Retention |
|---|---|---|
| User id (random UUIDv7) | Primary key | Until account deletion + 30 days legal hold if a report is open |
| Username | Discovery | Until change / deletion |
| Phone HMAC | Registration, anti-abuse | Until deletion |
| Profile display name, about, avatar id | Social | Until change / deletion |
| Device public keys | E2EE | Until device revoke + 7 days |
| Encrypted envelopes | Delivery | Until ACK or 30 days |
| Attachment ciphertext | Delivery | 90 days or earlier delete |
| Group membership | Fan-out | Until leave + 30 days |
| Push token (encrypted at rest) | Wakeup | Until logout / rotate |
| IP + user-agent (edge) | Abuse, TLS | 7 days |
| Reports | Safety | 180 days |
| Metrics (no ids) | SLO | 13 months |

We do **not** collect: precise location, address book (except on-device
hashed match the user initiates), message plaintext, analytics of content,
advertising ids.

## User rights

- Export of **profile and device list** from the server.
- Export of **message history** only from the device (server has no plaintext).
- Delete account: wipe profile, devices, mailboxes, objects we still hold,
  hashed phone. Irreversible.
- Delete a message for me / for everyone: server drops undelivered copies;
  delivered copies are a client-side delete request (not a guarantee against
  a hostile recipient).

## Push and OS surfaces

Default: hide content on lock screen, hide in app switcher, no cloud backup
of the message database. Users can relax this; we warn.

## Legal

A lawful request can obtain **metadata we actually have**. We cannot produce
plaintext we do not have. We will publish a transparency note before any
production launch in a jurisdiction. This is not legal advice.

## Children

OllO is not directed at children under 16. Age gate is a declaration plus
store policies. We do not build parental message-reading.
