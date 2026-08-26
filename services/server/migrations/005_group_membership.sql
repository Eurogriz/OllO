ALTER TABLE groups ADD COLUMN IF NOT EXISTS membership_epoch INTEGER;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS membership_json TEXT;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS membership_sig BYTEA;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS membership_signer_user_id UUID;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS membership_signer_device_id UUID;
