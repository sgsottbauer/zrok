-- +migrate Up

-- Add OAuth fields to accounts table
ALTER TABLE accounts ADD COLUMN oauth_provider VARCHAR(128);
ALTER TABLE accounts ADD COLUMN oauth_subject VARCHAR(256);

-- Make password and salt nullable for OAuth accounts
ALTER TABLE accounts ALTER COLUMN password DROP NOT NULL;
ALTER TABLE accounts ALTER COLUMN salt DROP NOT NULL;

-- Add unique constraint for OAuth accounts (one account per provider+subject)
CREATE UNIQUE INDEX accounts_oauth_provider_subject_idx
  ON accounts(oauth_provider, oauth_subject)
  WHERE oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL;

-- Add comments for documentation
COMMENT ON COLUMN accounts.oauth_provider IS 'OAuth provider identifier (e.g., "oidc:https://accounts.google.com", "google", "github")';
COMMENT ON COLUMN accounts.oauth_subject IS 'OAuth subject/user ID from the provider (unique per provider)';
