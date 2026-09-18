# ADR-001: Modular Monolith over Microservices

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust performs document upload, cryptographic signing, signature
verification, certificate/trust evaluation and audit logging. A common instinct
for a system with these distinct capabilities is to split them into separate
services — a signing service, a verification service, a document service.

The forces actually at play here:

- The dominant engineering risk is **cryptographic and trust-evaluation
  correctness**, not throughput or independent scaling.
- The core demonstration flow (upload → sign → verify → tamper → detect) crosses
  every module. It must be testable end-to-end, deterministically, in CI.
- Signing and verification share substantial domain vocabulary: certificates,
  digests, byte ranges, trust anchors, revocation status.
- The audit log must record events from every module with a consistent,
  gap-free hash chain.
- This is a single team, single deployment, single database.

## Decision

Build a **modular monolith**: one Spring Boot deployable, internally divided
into feature modules (`document`, `signature`, `verification`, `certificate`,
`audit`, `timestamp`, `storage`, `security`, `common`), each with its own
`api` / `application` / `domain` / `infrastructure` packages.

Boundaries are enforced by convention and package structure: modules
communicate through application-service interfaces and never reach into another
module's `domain` or `infrastructure` internals.

## Alternatives considered

**Microservices from the start.** Rejected. It would introduce network calls on
the critical signing path, distributed failure modes, and cross-service
transactions — all while the actual difficulty (PAdES correctness, chain
validation, tamper analysis) remains exactly as hard. The audit hash chain in
particular becomes materially harder to keep gap-free across service
boundaries, since appends would need distributed ordering.

**Layered monolith** (`controller/`, `service/`, `repository/`). Rejected.
Technical-layer packaging scatters each feature across the tree, hides cohesion,
and makes later extraction of a module into its own service impractical because
nothing marks where one capability ends and the next begins.

**Serverless functions per operation.** Rejected. Signing needs warm access to
key material and loaded cryptographic providers; cold starts and key-handling
across ephemeral function instances add risk without benefit at this scale.

## Consequences

**Positive**
- The full demonstration flow runs in a single process and is testable end-to-end.
- One transaction manager; audit chain appends are straightforward to keep ordered.
- Shared domain vocabulary lives in one place — no cross-service DTO duplication.
- Simple local development: one backend to run and debug.
- Module boundaries make future extraction a refactor, not a rewrite.

**Negative**
- The whole application scales as one unit. If verification ever becomes a
  throughput bottleneck, it cannot scale independently without extraction first.
- Module boundaries rest on discipline rather than compiler enforcement. A
  careless import can cross a boundary and nothing fails the build today.
- A single deployable means a fault in any module can affect the whole process.

**Mitigations**
- Package structure makes boundary violations visible in review.
- If enforcement becomes necessary, ArchUnit tests or Spring Modulith can assert
  the boundaries without restructuring the code.
