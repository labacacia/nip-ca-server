-- NIP CA Server — RA model schema (NPS-CR-0005)
-- Copyright 2026 INNO LOTUS PTY LTD | Apache-2.0

-- ── Tier 2: Bootstrap tokens ─────────────────────────────────────────────────
-- Plaintext tokens are NEVER stored — only the SHA-256 hex hash.
-- A token is single-use; once `consumed = true` it cannot be presented again.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'nip_bootstrap_tokens'
          AND column_name IN ('token_id', 'hashed_token', 'used')
    ) THEN
        ALTER TABLE nip_bootstrap_tokens
            RENAME TO nip_bootstrap_tokens_legacy_alpha15;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'nip_pending_requests'
          AND column_name IN ('pending_id', 'nid', 'submitted_at')
    ) THEN
        ALTER TABLE nip_pending_requests
            RENAME TO nip_pending_requests_legacy_alpha15;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS nip_bootstrap_tokens (
    id          TEXT         PRIMARY KEY,       -- stable ID for audit/revocation
    token_hash  TEXT         NOT NULL UNIQUE,   -- hex SHA-256 of the plaintext token
    label       TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    consumed    BOOLEAN      NOT NULL DEFAULT false,
    revoked     BOOLEAN      NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_nip_bootstrap_tokens_hash
    ON nip_bootstrap_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_nip_bootstrap_tokens_expires
    ON nip_bootstrap_tokens (expires_at);

-- ── Tier 3: Pending registration requests ────────────────────────────────────
-- Agents submit a registration request; an operator approves or rejects it.
-- After a decision the row is kept for audit; agents poll by pending_id.

CREATE TABLE IF NOT EXISTS nip_pending_requests (
    id            TEXT         PRIMARY KEY,
    entity_type   TEXT         NOT NULL CHECK (entity_type IN ('agent', 'node')),
    identifier    TEXT         NOT NULL,
    pub_key       TEXT         NOT NULL,
    capabilities  TEXT[]       NOT NULL DEFAULT '{}',
    scope_json    JSONB        NOT NULL DEFAULT '{}',
    metadata_json JSONB,
    requested_at  TIMESTAMPTZ  NOT NULL,
    status        TEXT         NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'approved', 'rejected')),
    reject_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_nip_pending_requests_status
    ON nip_pending_requests (status, requested_at);
CREATE INDEX IF NOT EXISTS idx_nip_pending_requests_identifier
    ON nip_pending_requests (identifier);
