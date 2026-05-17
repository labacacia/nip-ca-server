-- NIP CA Server — RA model migration (NPS-CR-0005)
-- Copyright 2026 INNO LOTUS PTY LTD | Apache-2.0

-- ── Bootstrap token store (Tier 2) ────────────────────────────────────────────
-- Raw token values are NEVER stored; only their SHA-256 hash.

CREATE TABLE IF NOT EXISTS nip_bootstrap_tokens (
    id            TEXT         PRIMARY KEY,
    token_hash    BYTEA        NOT NULL,
    label         TEXT,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ  NOT NULL,
    consumed      BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked       BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_nip_bootstrap_tokens_expires
    ON nip_bootstrap_tokens (expires_at)
    WHERE consumed = FALSE AND revoked = FALSE;

-- ── Pending registration queue (Tier 3) ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS nip_pending_registrations (
    id             TEXT         PRIMARY KEY,
    entity_type    TEXT         NOT NULL CHECK (entity_type IN ('agent', 'node')),
    identifier     TEXT         NOT NULL,
    pub_key        TEXT         NOT NULL,
    capabilities   TEXT[]       NOT NULL DEFAULT '{}',
    scope_json     JSONB        NOT NULL DEFAULT '{}',
    metadata_json  JSONB,
    requested_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status         TEXT         NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'rejected')),
    reject_reason  TEXT
);

CREATE INDEX IF NOT EXISTS idx_nip_pending_status
    ON nip_pending_registrations (status, requested_at DESC);
