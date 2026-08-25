CREATE TABLE IF NOT EXISTS backups (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  payload BYTEA NOT NULL,
  size INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS backups_user ON backups (user_id, created_at DESC);

ALTER TABLE calls ADD COLUMN group_id UUID;
