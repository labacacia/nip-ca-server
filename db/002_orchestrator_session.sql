-- NIP CA Server — Orchestrator group + session NIDs (NPS-CR-0003)
-- Adds the lineage columns and the parent_nid index used for cascade
-- revocation and the audit endpoint
--   GET /v1/orchestrators/groups/{group_nid}/sessions
--
-- Idempotent: every change uses IF NOT EXISTS so re-running on an
-- already-migrated database is a no-op.
--
-- Apply BEFORE upgrading the binary to v1.0-alpha.6 — the new code path
-- writes nid_role / parent_nid / lineage_json on every group / session
-- registration and will fail INSERTs against a pre-migration schema.
--
-- NPS-3 §5.1.3 | Copyright 2026 INNO LOTUS PTY LTD | Apache-2.0

ALTER TABLE nip_certificates
    ADD COLUMN IF NOT EXISTS nid_role     TEXT,
    ADD COLUMN IF NOT EXISTS parent_nid   TEXT,
    ADD COLUMN IF NOT EXISTS lineage_json JSONB;

-- Cascade revocation enumerates every session under a revoked group.
-- The audit list endpoint uses the same index. Partial index keeps the
-- size proportional to the number of sessions rather than the full
-- nip_certificates table.
CREATE INDEX IF NOT EXISTS idx_nip_certs_parent_nid
    ON nip_certificates (parent_nid)
    WHERE parent_nid IS NOT NULL;

-- Defensive: bound nid_role to the values the spec defines. Future
-- multi-level chains (sub-group, etc.) extend this CHECK in a follow-up
-- migration.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'nip_certificates_nid_role_check'
    ) THEN
        ALTER TABLE nip_certificates
            ADD CONSTRAINT nip_certificates_nid_role_check
            CHECK (nid_role IS NULL OR nid_role IN ('group', 'session'));
    END IF;
END $$;
