-- Addendum D: Tamper-evident audit hash chains.
-- Run this on existing databases.

ALTER TABLE audit_log
  ADD COLUMN IF NOT EXISTS prev_hash TEXT,
  ADD COLUMN IF NOT EXISTS entry_hash TEXT,
  ADD COLUMN IF NOT EXISTS signature TEXT;

ALTER TABLE fs_audit_log
  ADD COLUMN IF NOT EXISTS prev_hash TEXT,
  ADD COLUMN IF NOT EXISTS entry_hash TEXT,
  ADD COLUMN IF NOT EXISTS signature TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_log_entry_hash ON audit_log (entry_hash);
CREATE INDEX IF NOT EXISTS idx_fs_audit_log_entry_hash ON fs_audit_log (entry_hash);
