CREATE TABLE IF NOT EXISTS username_changes (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS username_changes_user_day
  ON username_changes (user_id, changed_at);
