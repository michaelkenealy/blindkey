-- Addendum A Phase 1: allowed_domains and injection_ttl_seconds
-- Run this on existing databases to add the new columns.
-- New installs use the updated schema.sql directly.

ALTER TABLE secrets
  ADD COLUMN IF NOT EXISTS allowed_domains TEXT[] DEFAULT NULL,
  ADD COLUMN IF NOT EXISTS injection_ttl_seconds INT NOT NULL DEFAULT 1800;
