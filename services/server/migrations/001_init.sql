-- OllO schema. Server stores metadata and opaque ciphertext only.
-- No plaintext message bodies, no private keys, no attachment keys.

CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  username TEXT UNIQUE,
  phone_hmac TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  about TEXT NOT NULL DEFAULT '',
  avatar_object_id TEXT,
  registration_lock_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS users_username_lower ON users (lower(username));

CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  registration_id INTEGER NOT NULL,
  identity_x25519 BYTEA NOT NULL,
  identity_ed25519 BYTEA NOT NULL,
  signed_prekey_id INTEGER NOT NULL,
  signed_prekey_public BYTEA NOT NULL,
  signed_prekey_sig BYTEA NOT NULL,
  push_token_enc BYTEA,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS devices_user ON devices (user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS one_time_prekeys (
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL,
  public_key BYTEA NOT NULL,
  consumed_at TIMESTAMPTZ,
  PRIMARY KEY (device_id, key_id)
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id TEXT PRIMARY KEY,
  phone_hmac TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  device_fingerprint TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS otp_phone ON otp_challenges (phone_hmac, created_at DESC);

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  device_id UUID NOT NULL REFERENCES devices(id),
  refresh_hash TEXT NOT NULL UNIQUE,
  family_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  replaced_by UUID
);

CREATE INDEX IF NOT EXISTS sessions_device ON sessions (device_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS envelopes (
  id UUID PRIMARY KEY,
  sender_user_id UUID NOT NULL,
  sender_device_id UUID NOT NULL,
  recipient_user_id UUID NOT NULL,
  recipient_device_id UUID NOT NULL,
  group_id UUID,
  kind TEXT NOT NULL,
  payload BYTEA NOT NULL,
  padding_bucket INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  acked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS envelopes_mailbox
  ON envelopes (recipient_device_id, created_at)
  WHERE acked_at IS NULL;

CREATE TABLE IF NOT EXISTS groups (
  id UUID PRIMARY KEY,
  creator_id UUID NOT NULL REFERENCES users(id),
  epoch INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS group_members (
  group_id UUID NOT NULL REFERENCES groups(id),
  user_id UUID NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'member',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  removed_at TIMESTAMPTZ,
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS group_invites (
  token_hash TEXT PRIMARY KEY,
  group_id UUID NOT NULL REFERENCES groups(id),
  created_by UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS contacts (
  user_id UUID NOT NULL REFERENCES users(id),
  contact_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, contact_user_id)
);

CREATE TABLE IF NOT EXISTS blocks (
  user_id UUID NOT NULL REFERENCES users(id),
  blocked_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, blocked_user_id)
);

CREATE TABLE IF NOT EXISTS mutes (
  user_id UUID NOT NULL REFERENCES users(id),
  thread_id TEXT NOT NULL,
  until TIMESTAMPTZ,
  PRIMARY KEY (user_id, thread_id)
);

CREATE TABLE IF NOT EXISTS archives (
  user_id UUID NOT NULL REFERENCES users(id),
  thread_id TEXT NOT NULL,
  archived_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, thread_id)
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY,
  reporter_id UUID NOT NULL,
  reportee_id UUID NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attachments (
  id UUID PRIMARY KEY,
  uploader_device_id UUID NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  digest BYTEA,
  size BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS attachment_grants (
  token_hash TEXT PRIMARY KEY,
  attachment_id UUID NOT NULL REFERENCES attachments(id),
  recipient_user_id UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS calls (
  id UUID PRIMARY KEY,
  created_by UUID NOT NULL,
  media TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS call_participants (
  call_id UUID NOT NULL REFERENCES calls(id),
  user_id UUID NOT NULL,
  device_id UUID NOT NULL,
  PRIMARY KEY (call_id, device_id)
);

CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS drafts (
  user_id UUID NOT NULL,
  device_id UUID NOT NULL,
  thread_id TEXT NOT NULL,
  ciphertext BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, device_id, thread_id)
);
