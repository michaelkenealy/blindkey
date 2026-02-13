-- AgentVault Database Schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users (email);

-- Secrets table
CREATE TABLE secrets (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  vault_ref         TEXT UNIQUE NOT NULL,
  name              TEXT NOT NULL,
  service           TEXT NOT NULL,
  secret_type       TEXT NOT NULL CHECK (secret_type IN ('api_key', 'oauth_token', 'basic_auth', 'custom_header', 'query_param')),
  encrypted_value   BYTEA NOT NULL,
  iv                BYTEA NOT NULL,
  auth_tag          BYTEA NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ,
  metadata          JSONB DEFAULT '{}'::jsonb,
  allowed_domains   TEXT[],
  injection_ttl_seconds INT NOT NULL DEFAULT 1800
);

CREATE INDEX idx_secrets_user_id ON secrets (user_id);
CREATE INDEX idx_secrets_vault_ref ON secrets (vault_ref);

-- Policy sets
CREATE TABLE policy_sets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  rules       JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_sets_user_id ON policy_sets (user_id);

-- Agent sessions
CREATE TABLE agent_sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash      TEXT UNIQUE NOT NULL,
  allowed_secrets TEXT[] NOT NULL DEFAULT '{}',
  policy_set_id   UUID REFERENCES policy_sets(id) ON DELETE SET NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  metadata        JSONB DEFAULT '{}'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_agent_sessions_user_id ON agent_sessions (user_id);
CREATE INDEX idx_agent_sessions_token_hash ON agent_sessions (token_hash);
CREATE INDEX idx_agent_sessions_expires_at ON agent_sessions (expires_at);

-- Audit log (append-only)
CREATE TABLE audit_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id      UUID REFERENCES agent_sessions(id) ON DELETE SET NULL,
  vault_ref       TEXT,
  action          TEXT NOT NULL,
  request_summary JSONB,
  policy_result   JSONB,
  response_status INT,
  latency_ms      INT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_user_id ON audit_log (user_id);
CREATE INDEX idx_audit_log_session_id ON audit_log (session_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
CREATE INDEX idx_audit_log_vault_ref ON audit_log (vault_ref);

-- Prevent updates and deletes on audit_log
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % operations are not allowed', TG_OP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER audit_log_no_delete
  BEFORE DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Approval queue
CREATE TABLE approval_queue (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id      UUID NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
  vault_ref       TEXT NOT NULL,
  request_payload JSONB NOT NULL,
  policy_trigger  TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
  expires_at      TIMESTAMPTZ NOT NULL,
  resolved_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_approval_queue_user_id ON approval_queue (user_id);
CREATE INDEX idx_approval_queue_status ON approval_queue (status);
CREATE INDEX idx_approval_queue_expires_at ON approval_queue (expires_at);

-- Filesystem grants per session
CREATE TABLE filesystem_grants (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id        UUID NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
  path              TEXT NOT NULL,
  permissions       TEXT[] NOT NULL,
  recursive         BOOLEAN NOT NULL DEFAULT true,
  requires_approval BOOLEAN NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_filesystem_grants_session_id ON filesystem_grants (session_id);

-- Filesystem audit log (append-only)
CREATE TABLE fs_audit_log (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id        UUID REFERENCES agent_sessions(id) ON DELETE SET NULL,
  operation         TEXT NOT NULL,
  path              TEXT NOT NULL,
  granted           BOOLEAN NOT NULL,
  blocking_rule     TEXT,
  bytes_transferred BIGINT,
  file_hash         TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_fs_audit_log_session_id ON fs_audit_log (session_id);
CREATE INDEX idx_fs_audit_log_created_at ON fs_audit_log (created_at);

CREATE TRIGGER fs_audit_log_no_update
  BEFORE UPDATE ON fs_audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER fs_audit_log_no_delete
  BEFORE DELETE ON fs_audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
