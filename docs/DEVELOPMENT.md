# Development

## Prerequisites

- Node.js 22+
- npm 10+
- Optional: Docker (only for Postgres / Redis / MinIO / coturn that mirror
  production). Local default uses PGlite and in-memory Redis fallback.

## First run

```bash
cp .env.example .env
npm install
npm run dev:all
```

- API: http://localhost:8080
- Web: http://localhost:5173
- Health: http://localhost:8080/healthz

Register two users in two browser profiles. In development the OTP is
returned in the `request-otp` JSON field `dev_otp`.

## Commands

| Command | What |
|---|---|
| `npm run dev` | API + WS only |
| `npm run dev:web` | Vite client |
| `npm run dev:all` | both |
| `npm test` | all workspace tests |
| `npm run test:crypto` | protocol / crypto |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run migrate` | apply SQL migrations |

## Layout

- Protocol types: `packages/protocol`
- Crypto engine: `packages/crypto`
- Server modules: `services/server/src/modules/*`
- Web client: `apps/web`
- Android: `apps/android`
- iOS: `apps/ios`

## Rules

- Never commit `.env`, keystores, `google-services.json`, or real OTP logs.
- Never log tokens, keys, OTP, or message plaintext.
- New tables go through `services/server/migrations/`.
- New envelope fields must be additive and versioned.
- Crypto changes require a test and an update to `CRYPTOGRAPHY.md`.

## Without Docker

PGlite stores data in `./data/pglite`. Delete that directory to reset.

## With Docker (staging-like)

```bash
docker compose -f infrastructure/docker/docker-compose.yml up -d
# then set DATABASE_DRIVER=postgresql and REDIS_URL in .env
```

## Mobile

See [RELEASE.md](RELEASE.md). Android needs JDK 17 + Android SDK.
iOS needs macOS + Xcode. This Linux environment cannot produce a signed IPA.

Native launch restores `SessionVault` via `SessionHost`. A stored session
opens the inbox. OTP is not requested until a bound libsignal engine can
emit `deviceRegistrationJson`. iOS `AuthRepository.connected` persists
verify-otp tokens into the vault and wipes on a rejected refresh. This
environment cannot run `./gradlew test` or Xcode tests.
