# ADR-003: Document Bytes in Object Storage, Not the Database

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust stores original PDFs, each signed version, and generated reports. A signed PDF
in this build is roughly 35 KB, but production documents routinely reach tens of megabytes,
and every signature creates a new version rather than replacing the old one.

## Decision

Store document bytes in object storage behind a `DocumentStorage` interface. Store only
metadata, versions, signature records and the audit chain in PostgreSQL.

Two implementations: `FilesystemDocumentStorage` for local development and CI, and
`MinioDocumentStorage` for the S3-compatible production path.

## Alternatives considered

**BLOBs in PostgreSQL.** Rejected. Large binaries inflate backups and WAL, slow
replication, and push multi-megabyte payloads through the connection pool on every read.
Transactional consistency between metadata and bytes is the one real benefit, and it does
not outweigh the operational cost.

**Filesystem only.** Rejected for production. It works locally but does not survive
container restarts without a volume, does not scale horizontally, and provides no
lifecycle or replication features.

## Consequences

**Positive**
- The database stays small and fast; queries return metadata without touching document bytes.
- Storage scales independently, and S3, GCS or Azure Blob are drop-in implementations.
- Local development and CI need no object store at all.

**Negative**
- Metadata and bytes are no longer written in one transaction. A crash between the two can
  leave an orphaned object or a metadata row pointing at nothing. The current mitigation is
  ordering — bytes are written before metadata is committed, so the failure mode is a
  harmless orphaned object rather than a dangling reference. A reconciliation job is not
  implemented.
- Two systems to back up, and their backups must be consistent with each other.

**Status note.** `MinioDocumentStorage` is **not implemented** in this build. Selecting the
MinIO backend fails loudly at startup rather than silently writing documents somewhere
unexpected.
