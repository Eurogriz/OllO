DROP TABLE IF EXISTS idempotency;
CREATE TABLE idempotency (
  scope TEXT NOT NULL,
  key TEXT NOT NULL,
  status INTEGER NOT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, key)
);
CREATE INDEX IF NOT EXISTS idempotency_created ON idempotency (created_at);
