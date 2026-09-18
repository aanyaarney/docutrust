-- ---------------------------------------------------------------------------
-- DocuTrust initial schema
--
-- Written in portable SQL so the same migrations run against both PostgreSQL
-- (docker / production) and H2 (local development and CI). That is deliberate:
-- migrations that only ever run on one engine are migrations nobody has tested.
--
-- Document bytes are NOT stored here. Only metadata, signatures, verification
-- outcomes and the audit chain. PDFs live in object storage.
-- ---------------------------------------------------------------------------

-- ============================ Users ========================================
CREATE TABLE users (
    id              VARCHAR(36)   NOT NULL,
    email           VARCHAR(255)  NOT NULL,
    display_name    VARCHAR(255)  NOT NULL,
    password_hash   VARCHAR(255)  NOT NULL,
    role            VARCHAR(32)   NOT NULL,
    enabled         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP     NOT NULL,
    CONSTRAINT pk_users PRIMARY KEY (id),
    CONSTRAINT uq_users_email UNIQUE (email)
);

-- ========================== Documents ======================================
CREATE TABLE documents (
    id              VARCHAR(36)   NOT NULL,
    file_name       VARCHAR(512)  NOT NULL,
    owner_id        VARCHAR(36)   NOT NULL,
    size_bytes      BIGINT        NOT NULL,
    sha256          VARCHAR(64)   NOT NULL,
    page_count      INTEGER,
    content_type    VARCHAR(128)  NOT NULL,
    signature_state VARCHAR(32)   NOT NULL,
    uploaded_at     TIMESTAMP     NOT NULL,
    CONSTRAINT pk_documents PRIMARY KEY (id),
    CONSTRAINT fk_documents_owner FOREIGN KEY (owner_id) REFERENCES users (id)
);

-- Owner + recency drives the document list, the most frequent query.
CREATE INDEX idx_documents_owner       ON documents (owner_id);
CREATE INDEX idx_documents_uploaded_at ON documents (uploaded_at);
CREATE INDEX idx_documents_state       ON documents (signature_state);
CREATE INDEX idx_documents_sha256      ON documents (sha256);

-- ====================== Document versions ==================================
-- Version 0 is the original upload; each signature appends a new version.
CREATE TABLE document_versions (
    id              VARCHAR(36)   NOT NULL,
    document_id     VARCHAR(36)   NOT NULL,
    version_number  INTEGER       NOT NULL,
    storage_key     VARCHAR(1024) NOT NULL,
    sha256          VARCHAR(64)   NOT NULL,
    size_bytes      BIGINT        NOT NULL,
    signed          BOOLEAN       NOT NULL,
    created_at      TIMESTAMP     NOT NULL,
    CONSTRAINT pk_document_versions PRIMARY KEY (id),
    CONSTRAINT fk_versions_document FOREIGN KEY (document_id) REFERENCES documents (id),
    CONSTRAINT uq_versions_document_number UNIQUE (document_id, version_number)
);

CREATE INDEX idx_versions_document ON document_versions (document_id);

-- ========================= Signatures ======================================
CREATE TABLE signature_records (
    id                   VARCHAR(36)   NOT NULL,
    document_id          VARCHAR(36)   NOT NULL,
    document_version_id  VARCHAR(36)   NOT NULL,
    signer_user_id       VARCHAR(36),
    signer_common_name   VARCHAR(512),
    certificate_subject  VARCHAR(1024),
    certificate_issuer   VARCHAR(1024),
    certificate_serial   VARCHAR(128),
    signature_algorithm  VARCHAR(64)   NOT NULL,
    digest_algorithm     VARCHAR(64)   NOT NULL,
    signature_format     VARCHAR(64)   NOT NULL,
    provider_name        VARCHAR(64)   NOT NULL,
    reason               VARCHAR(512),
    location             VARCHAR(512),
    signed_at            TIMESTAMP     NOT NULL,
    CONSTRAINT pk_signature_records PRIMARY KEY (id),
    CONSTRAINT fk_signatures_document FOREIGN KEY (document_id) REFERENCES documents (id),
    CONSTRAINT fk_signatures_version  FOREIGN KEY (document_version_id) REFERENCES document_versions (id)
);

CREATE INDEX idx_signatures_document ON signature_records (document_id);
CREATE INDEX idx_signatures_signed_at ON signature_records (signed_at);

-- ======================== Verifications ====================================
CREATE TABLE verification_records (
    id                VARCHAR(36)   NOT NULL,
    verification_id   VARCHAR(64)   NOT NULL,
    document_id       VARCHAR(36),
    requested_by      VARCHAR(36),
    file_name         VARCHAR(512),
    document_sha256   VARCHAR(64)   NOT NULL,
    verdict           VARCHAR(32)   NOT NULL,
    signature_count   INTEGER       NOT NULL,
    tampering_detected BOOLEAN      NOT NULL,
    report_json       VARCHAR(16384),
    verified_at       TIMESTAMP     NOT NULL,
    CONSTRAINT pk_verification_records PRIMARY KEY (id),
    CONSTRAINT uq_verification_public_id UNIQUE (verification_id)
);

CREATE INDEX idx_verifications_document ON verification_records (document_id);
CREATE INDEX idx_verifications_verdict  ON verification_records (verdict);
CREATE INDEX idx_verifications_time     ON verification_records (verified_at);

-- ====================== Audit chain ========================================
-- Append-only by policy. `sequence_number` is contiguous and gap-free; the
-- hash chain makes any retroactive edit, insertion or deletion detectable.
CREATE TABLE audit_events (
    id                   VARCHAR(36)   NOT NULL,
    sequence_number      BIGINT        NOT NULL,
    event_type           VARCHAR(64)   NOT NULL,
    document_id          VARCHAR(36),
    user_id              VARCHAR(36),
    ip_address           VARCHAR(64),
    correlation_id       VARCHAR(64),
    details              VARCHAR(2048),
    previous_record_hash VARCHAR(64)   NOT NULL,
    record_hash          VARCHAR(64)   NOT NULL,
    occurred_at          TIMESTAMP     NOT NULL,
    CONSTRAINT pk_audit_events PRIMARY KEY (id),
    CONSTRAINT uq_audit_sequence UNIQUE (sequence_number)
);

CREATE INDEX idx_audit_document   ON audit_events (document_id);
CREATE INDEX idx_audit_occurred   ON audit_events (occurred_at);
CREATE INDEX idx_audit_event_type ON audit_events (event_type);
