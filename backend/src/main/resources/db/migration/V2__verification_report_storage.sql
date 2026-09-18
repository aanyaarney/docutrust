-- ---------------------------------------------------------------------------
-- Full verification reports, stored so a report can be re-opened and shared by
-- its verification ID without re-uploading the document.
--
-- A separate table rather than widening verification_records.report_json:
-- ALTER COLUMN type syntax differs between PostgreSQL and H2, and these
-- migrations must run unchanged on both (see ADR-006). CREATE TABLE is portable.
--
-- The report is stored as JSON rather than as parsed columns because it is
-- written once and read whole. Shredding it into columns would add schema
-- coupling for no query benefit.
-- ---------------------------------------------------------------------------

CREATE TABLE verification_reports (
    verification_id VARCHAR(64)     NOT NULL,
    report_json     VARCHAR(1000000) NOT NULL,
    created_at      TIMESTAMP       NOT NULL,
    CONSTRAINT pk_verification_reports PRIMARY KEY (verification_id)
);

CREATE INDEX idx_verification_reports_created ON verification_reports (created_at);
