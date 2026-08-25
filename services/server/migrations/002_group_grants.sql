-- Group-scoped attachment grants: one token any current member can present.
ALTER TABLE attachment_grants ADD COLUMN group_id UUID;
ALTER TABLE attachment_grants ALTER COLUMN recipient_user_id DROP NOT NULL;
