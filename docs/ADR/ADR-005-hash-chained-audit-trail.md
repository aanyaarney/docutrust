# ADR-005: Hash-Chained Audit Trail

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust's audit log records who signed what and when. That log is itself a target: an
attacker who alters a document would also want to erase the trace. A plain append-only
table offers no way to detect a retroactive edit, because a row that has been quietly
updated looks exactly like one that has not.

## Decision

Chain audit records with SHA-256:

```
recordHash = SHA-256( previousRecordHash + canonicalEventData )
```

Each record stores both its own hash and its predecessor's.
`AuditIntegrityService.verifyChain()` recomputes the chain and reports the first record
that fails.

The canonical form is **length-prefixed** (each field encoded as its byte length, a colon,
the value, a semicolon) rather than separator-joined. With a plain separator, the field
pairs `("a" + sep + "b", "c")` and `("a", "b" + sep + "c")` serialise identically and
therefore hash identically — an attacker controlling part of one field could shift a
boundary and rewrite a record while keeping its hash intact. Length prefixing gives every
distinct field tuple exactly one encoding. This is tested directly.

Timestamps are truncated to milliseconds before hashing, because a SQL `TIMESTAMP` column
stores at most microseconds while `Instant.now()` carries nanoseconds. Hashing an
untruncated value produces records that fail to recompute after a database round trip.
That defect was found by running the system, and a persistence round-trip test now guards
against it.

We call this a **hash-chained tamper-evident log**. We do not call it a blockchain.

## Alternatives considered

**Plain append-only table.** Rejected — no detection of edits.

**Database triggers preventing UPDATE and DELETE.** Useful defence in depth, but bypassed
by anyone with sufficient privileges, and offers no detection after the fact. Complementary
rather than sufficient.

**Digitally signing each audit record.** Stronger, since detection would not depend on the
attacker lacking a key. Rejected for now: it puts a signing operation on every audited
action and entangles the audit subsystem with key management. Worth revisiting.

**An actual distributed ledger.** Rejected as disproportionate. It would add consensus
infrastructure to a single-tenant application, and calling a hash chain a "blockchain"
would overstate the guarantee.

## Consequences

**Positive**
- Any single-point edit, deletion or insertion is detectable by recomputation.
- Cheap: one SHA-256 per event.
- Chain status is a visible product feature on the dashboard.

**Negative**
- Appends must serialise, since each record depends on the current head. The lock is
  per-JVM: correct for one instance, **incorrect across multiple instances**, where it
  would fork the chain. Database-level serialisation is required before horizontal scaling.
- Verification is linear over the whole log; it will need checkpointing as the log grows.
- **The guarantee is evidence, not prevention.** An attacker with full database write
  access can recompute the chain from their edit onward and leave it consistent. Closing
  that gap requires publishing chain heads to independent storage or timestamping them
  with a TSA — neither is implemented, and the limitation is stated in the UI rather than
  glossed over.
