-- Addendum B: Filesystem grants and audit tables.
-- Run this on existing databases.

CREATE TABLE IF NOT EXISTS filesystem_grants (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id        UUID NOT NULL REFERENCES agent_sessions(id) ON DELETE CASCADE,
  path              TEXT NOT NULL,
  permissions       TEXT[] NOT NULL,
  recursive         BOOLEAN NOT NULL DEFAULT true,
  requires_approval BOOLEAN NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_filesystem_grants_session_id ON filesystem_grants (session_id);

CREATE TABLE IF NOT EXISTS fs_audit_log (
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

CREATE INDEX IF NOT EXISTS idx_fs_audit_log_session_id ON fs_audit_log (session_id);
CREATE INDEX IF NOT EXISTS idx_fs_audit_log_created_at ON fs_audit_log (created_at);

CREATE TRIGGER fs_audit_log_no_update
  BEFORE UPDATE ON fs_audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER fs_audit_log_no_delete
  BEFORE DELETE ON fs_audit_log
  FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
