-- Addendum C: Auth login throttling and lockout state.
-- Run this on existing databases.

CREATE TABLE IF NOT EXISTS auth_login_attempts (
  bucket          TEXT PRIMARY KEY,
  failed_count    INT NOT NULL DEFAULT 0,
  first_failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_failed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_until    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_locked_until ON auth_login_attempts (locked_until);
