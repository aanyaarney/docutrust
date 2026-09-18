# ADR-006: PostgreSQL for Metadata, Flyway for Schema

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust stores users, documents, versions, signature records, verification outcomes and
the audit chain. These are highly relational: versions belong to documents, signatures to
versions, and the audit chain requires strict ordering by a unique sequence number.

## Decision

Use **PostgreSQL** in production and **H2 in PostgreSQL compatibility mode** for local
development and CI. Own the schema with **Flyway migrations**; run Hibernate with
`ddl-auto=validate` so it can never generate or mutate schema.

Migrations are written in portable SQL that runs on both engines.

## Alternatives considered

**Hibernate schema generation (`ddl-auto=update`).** Rejected. It produces a schema nobody
reviewed, silently diverges between environments, and cannot express a data migration.
Schema changes to a table holding an audit chain deserve to be explicit and reviewed.

**A document database.** Rejected. The data is relational, and the audit chain needs a
unique, gap-free sequence — a constraint relational databases enforce directly.

**H2 everywhere.** Rejected for production: in-memory by default, and its SQL dialect
differs from PostgreSQL in ways that would surface only in production.

**PostgreSQL everywhere including tests, via Testcontainers.** Reasonable, and the usual
advice. Rejected here for a specific reason: Docker is not available in the environment
this was built in, so container-backed tests could not have been executed. An untested
migration is worse than a portable one. Writing portable SQL means the migrations are
genuinely exercised on every local test run rather than merely asserted to work.

## Consequences

**Positive**
- Schema is reviewable, version-controlled and applied identically everywhere.
- Flyway migrations execute on every test run against H2, so they are real, tested code.
- Hibernate validates entity mappings against the actual schema at startup, catching drift
  immediately — this caught real column mismatches during development.
- Tests need no Docker and run in seconds.

**Negative**
- Migrations must avoid PostgreSQL-specific features such as `JSONB`, `SERIAL` and array
  types. Where those become necessary, this decision must be revisited and
  container-backed tests introduced.
- H2 compatibility mode is an approximation. Behavioural differences in locking, isolation
  or collation would not be caught locally.
