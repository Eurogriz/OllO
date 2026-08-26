CREATE TABLE IF NOT EXISTS call_invitees (
  call_id UUID NOT NULL REFERENCES calls(id),
  user_id UUID NOT NULL,
  PRIMARY KEY (call_id, user_id)
);
