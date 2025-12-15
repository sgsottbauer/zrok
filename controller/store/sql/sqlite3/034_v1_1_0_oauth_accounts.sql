-- +migrate Up

-- SQLite doesn't support ALTER COLUMN for NOT NULL constraints
-- We need to recreate the accounts table

-- Step 1: Create a new accounts table with OAuth support
CREATE TABLE accounts_new (
    id              INTEGER         PRIMARY KEY,
    email           VARCHAR(1024)   NOT NULL UNIQUE,
    salt            VARCHAR(16),
    password        VARCHAR(64),
    token           VARCHAR(32)     NOT NULL UNIQUE,
    limitless       BOOLEAN         NOT NULL DEFAULT(0),
    created_at      DATETIME        NOT NULL DEFAULT(CURRENT_TIMESTAMP),
    updated_at      DATETIME        NOT NULL DEFAULT(CURRENT_TIMESTAMP),
    deleted         BOOLEAN         NOT NULL DEFAULT(0),
    oauth_provider  VARCHAR(128),
    oauth_subject   VARCHAR(256)
);

-- Step 2: Copy data from old table
INSERT INTO accounts_new (id, email, salt, password, token, limitless, created_at, updated_at, deleted)
SELECT id, email, salt, password, token, limitless, created_at, updated_at, deleted
FROM accounts;

-- Step 3: Drop old table
DROP TABLE accounts;

-- Step 4: Rename new table
ALTER TABLE accounts_new RENAME TO accounts;

-- Step 5: Create unique index for OAuth accounts
CREATE UNIQUE INDEX accounts_oauth_provider_subject_idx
  ON accounts(oauth_provider, oauth_subject)
  WHERE oauth_provider IS NOT NULL AND oauth_subject IS NOT NULL;
