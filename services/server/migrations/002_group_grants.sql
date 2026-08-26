ALTER TABLE attachment_grants ADD COLUMN IF NOT EXISTS group_id UUID;
ALTER TABLE attachment_grants ALTER COLUMN recipient_user_id DROP NOT NULL;
