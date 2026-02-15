-- Add TOTP 2FA columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret      BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_iv          BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_auth_tag    BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled     BOOLEAN NOT NULL DEFAULT false;
