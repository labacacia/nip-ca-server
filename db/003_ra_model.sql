-- NIP CA Server — RA model schema (NPS-CR-0005)
-- Copyright 2026 INNO LOTUS PTY LTD | Apache-2.0

-- ── Tier 2: Bootstrap tokens ─────────────────────────────────────────────────
-- Plaintext tokens are NEVER stored — only the SHA-256 hex hash.
-- A token is single-use; once `used = true` it cannot be presented again.

CREATE TABLE IF NOT EXISTS nip_bootstrap_tokens (
    id             BIGSERIAL    PRIMARY KEY,
    token_id       TEXT         NOT NULL UNIQUE,           -- stable ID for audit/revocation
    nid            TEXT         NOT NULL,                  -- bound target NID
    hashed_token   TEXT         NOT NULL UNIQUE,           -- hex SHA-256 of the plaintext token
    expires_at     TIMESTAMPTZ  NOT NULL,
    used           BOOLEAN      NOT NULL DEFAULT false,
    capabilities   TEXT[]       NOT NULL DEFAULT '{}',
    scope_json     JSONB,
    metadata_json  JSONB,                                  -- audit-only; NOT in IdentFrame
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nip_tokens_nid         ON nip_bootstrap_tokens (nid);
CREATE INDEX IF NOT EXISTS idx_nip_tokens_expires     ON nip_bootstrap_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_nip_tokens_hashed      ON nip_bootstrap_tokens (hashed_token);

-- ── Tier 3: Pending registration requests ────────────────────────────────────
-- Agents submit a registration request; an operator approves or rejects it.
-- After a decision the row is kept for audit; agents poll by pending_id.

CREATE TABLE IF NOT EXISTS nip_pending_requests (
    id                   BIGSERIAL    PRIMARY KEY,
    pending_id           TEXT         NOT NULL UNIQUE,
    nid                  TEXT         NOT NULL,
    pub_key              TEXT         NOT NULL,
    capabilities         TEXT[]       NOT NULL DEFAULT '{}',
    scope_json           JSONB,
    metadata_json        JSONB,
    submitted_at         TIMESTAMPTZ  NOT NULL,
    status               TEXT         NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'approved', 'rejected')),
    reject_reason        TEXT,
    reject_code          TEXT,
    approver_operator_id TEXT,
    decided_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_nip_pending_status      ON nip_pending_requests (status, submitted_at);
CREATE INDEX IF NOT EXISTS idx_nip_pending_nid         ON nip_pending_requests (nid);
