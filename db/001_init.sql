-- NIP CA Server — PostgreSQL schema
-- NPS-3 §8 | Copyright 2026 INNO LOTUS PTY LTD | Apache-2.0

-- Serial sequence (atomic, monotonically increasing)
CREATE SEQUENCE IF NOT EXISTS nip_serial_seq START 1;

-- Certificate store
CREATE TABLE IF NOT EXISTS nip_certificates (
    id             BIGSERIAL    PRIMARY KEY,
    nid            TEXT         NOT NULL,
    entity_type    TEXT         NOT NULL CHECK (entity_type IN ('agent', 'node', 'operator')),
    serial         TEXT         NOT NULL UNIQUE,
    pub_key        TEXT         NOT NULL,
    capabilities   TEXT[]       NOT NULL DEFAULT '{}',
    scope_json     JSONB        NOT NULL DEFAULT '{}',
    issued_by      TEXT         NOT NULL,
    issued_at      TIMESTAMPTZ  NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  TEXT,
    metadata_json  JSONB,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Most queries look up the latest active cert by NID
CREATE INDEX IF NOT EXISTS idx_nip_certs_nid        ON nip_certificates (nid, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_nip_certs_serial      ON nip_certificates (serial);
CREATE INDEX IF NOT EXISTS idx_nip_certs_revoked     ON nip_certificates (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_nip_certs_expires     ON nip_certificates (expires_at);
