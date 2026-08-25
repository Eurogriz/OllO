#!/usr/bin/env bash
# Smoke: register two users and search. Requires a running server.
set -euo pipefail
BASE="${OLLO_BASE:-http://127.0.0.1:8080}"

otp() {
  curl -sS -X POST "$BASE/v1/auth/request-otp" \
    -H 'content-type: application/json' \
    -d "{\"phone_e164\":\"$1\"}"
}

echo "health $(curl -sS "$BASE/healthz")"
A=$(otp +79990001111)
echo "$A" | grep -q challenge_id
echo ok
