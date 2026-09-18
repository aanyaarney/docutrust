# DocuTrust — Implementation Summary

A factual account of what was built, what works, what was verified, and what was
deliberately left undone.

---

## 1. What was built

A working digital signature platform that applies real PAdES Baseline-B signatures to PDFs
and cryptographically proves whether a document changed after signing.

The complete flow runs end to end and was executed, not merely coded:

```
Upload → SHA-256 → Sign (PAdES-B-B) → Download → Verify: VALID
                                    → Tamper   → Verify: TAMPERED
```

In the tampered case the report correctly shows integrity `MODIFIED` and signature
`INVALID` while the certificate remains `VALID` and the chain `TRUSTED` — the distinction
the specification calls out in section 7.

---

## 2. Architecture

A **modular monolith**: one Spring Boot process partitioned into feature modules
(`document`, `signature`, `verification`, `certificate`, `audit`, `storage`, `security`,
`common`), each with `api` / `application` / `domain` / `infrastructure` packages. No
global `controller/service/repository` layering. Rationale in
[ADR-001](docs/ADR/ADR-001-modular-monolith.md).

Key abstractions:

| Interface | Purpose | Implementations |
|---|---|---|
| `SigningProvider` | Key custody | `Pkcs12SigningProvider` (HSM/KMS are designed-for extension points) |
| `DocumentStorage` | Document bytes | `FilesystemDocumentStorage` |
| `TrustAnchorProvider` | Configured trust | `InMemoryTrustAnchorProvider` |
| `RevocationService` | OCSP/CRL | `DisabledRevocationService` (reports `NOT_CHECKED`) |
| `DocumentHashService` | Digests | `Sha256DocumentHashService` (streaming) |

---

## 3. Technologies

**Backend** — Java 21, Spring Boot 3.5.3, Spring Security, Spring Data JPA, Flyway,
PostgreSQL / H2, Apache PDFBox 3.0.7, Bouncy Castle 1.80, jjwt 0.12.6, springdoc-openapi
2.8.6, Micrometer, JUnit 5, AssertJ.

**Frontend** — React 19, TypeScript (strict, `noUncheckedIndexedAccess`), Vite 7,
Material UI 7, TanStack Query, Axios, Recharts, Vitest, Testing Library.

All versions were resolved against Maven Central and npm rather than invented.

---

## 4. Cryptographic design

**Signing.** PDFBox performs an incremental update reserving a `/Contents` hole and
declaring a `/ByteRange` over the rest of the file. Bouncy Castle builds a detached CMS
SignedData with the PAdES-required `signing-certificate-v2` attribute, plus content-type,
message-digest and signing-time. The CMS is written into the reserved hole.

**Verification.** Six checks run independently and are reported independently:

| Check | Method |
|---|---|
| Document integrity | Digest recomputed over `/ByteRange`, compared with the signed digest |
| Signature | CMS verified against the signer certificate's **public key** |
| Certificate | Validity window, key usage, parse |
| Chain | JDK PKIX `CertPathBuilder` to configured trust anchors |
| Revocation | `RevocationService` — reports `NOT_CHECKED` when disabled |
| Timestamp | `TimestampInspector` reads the CMS unsigned attributes: `NOT_AVAILABLE` when no token exists, `NOT_CHECKED` when one exists but no TSA trust anchor is configured, `INVALID` when it cannot be parsed |

Two deliberate design decisions are worth highlighting:

1. **Verification uses the certificate's public key, not the certificate object.** Bouncy
   Castle's certificate-based verifier additionally rejects signatures whose claimed
   signing time falls outside the certificate's validity window, which would report an
   expired-certificate signature as a *broken signature*. That conflates two independent
   questions, so validity is evaluated separately by `CertificateValidationService`.

2. **Chain validation runs as of a time inside the signer's validity window.** A signature
   made in 2024 with a certificate that expired in 2025 was legitimate when made;
   validating at "now" would report the chain as broken and conflate age with
   untrustworthiness. Expiry is reported separately.

No cryptographic primitive is implemented in this repository
([ADR-007](docs/ADR/ADR-007-no-custom-cryptography.md)).

---

## 5. Security decisions

- **Trust is configured, never inherited from the document.** Embedded certificates are
  claims. A self-signed signature verifies cryptographically and reports
  `VALID_UNTRUSTED` — amber, not green.
- **Uncertainty is never rendered as safety.** `NOT_CHECKED` and `NOT_AVAILABLE` are
  distinct enum values, typed as literal unions in TypeScript, and guarded by tests that
  fail if either is ever presented as valid.
- **Three verdicts, not two.** Green / amber / red, each with icon + label + colour so no
  meaning depends on colour alone.
- **Upload validated by magic bytes**, not the client-declared content type; filenames
  sanitised; storage keys composed by the application.
- **Timing-safe login**: a dummy BCrypt comparison runs for unknown accounts so email
  addresses cannot be enumerated by response time.
- **Error responses carry a code, a written message and a correlation ID** — never stack
  traces, paths or configuration.
- **Audit log hash-chained** with length-prefixed canonicalisation, so field boundaries
  cannot be shifted to forge a colliding hash.

---

## 6. Features implemented

**Document** — PDF upload with magic-byte and structural validation, streaming SHA-256,
filesystem storage, metadata persistence, version history.

**Signing** — Real PAdES-B-B signatures, certificate chain embedded, signed PDF
downloadable and externally verifiable, multiple signatures via incremental update
(previous signatures preserved), optional visible signature block rendered at
bottom-right of the last page.

The visible block deliberately carries the wording "Appearance proves nothing — verify
this document", and never uses a tick or the word "verified". A block that asserted
validity would teach readers exactly the habit this product exists to break: a forged
document can carry an identical one.

**Verification** — Six independent checks, three-state verdict, tamper classification
separating cryptographic proof from structural observation, technical detail including the
raw `/ByteRange`.

**Security** — JWT auth, BCrypt(12), `USER`/`VERIFIER`/`ADMIN` roles, CORS, security
headers, correlation IDs, centralised error mapping, token-bucket rate limiting (per
address for login, per account for signing and verification).

**Reports** — Full verification reports stored and downloadable as a self-contained HTML
document or as JSON, with every interpolated value HTML-escaped.

**Audit** — Hash-chained tamper-evident log, chain verification endpoint, per-document
history, dashboard status.

**Frontend** — Login, dashboard with charts, documents table, upload, sign dialog,
verification page with report download, security dashboard with severity-ranked alerts,
certificate explorer with chain visualisation, audit timeline, dark and light modes,
skeleton loading, empty states, tooltips.

**Observability** — Actuator health and Prometheus metrics; counters and timers for
uploads, signings, verifications by verdict, and tampering, all with low-cardinality
labels only.

---

## 7. Features intentionally deferred

Listed plainly. A security tool that overstates itself is worse than one that does less.

| Feature | Status and reason |
|---|---|
| `MinioDocumentStorage` | **Not implemented.** Selecting the MinIO backend fails loudly at startup rather than writing documents somewhere unexpected. |
| RFC 3161 timestamp *creation* | `TimestampService` and `NoOpTimestampService` exist; no TSA client, so signatures are B-B. Verification does inspect submitted documents for a token. |
| OCSP / CRL | Interface exists; only `DisabledRevocationService`. Reports `NOT_CHECKED`. |
| Configurable appearance | The visible block is implemented, but with a fixed layout at bottom-right of the last page. Position and styling are not user-configurable. |
| QR code on reports | Not built. |
| SoftHSM / AWS / Azure / GCP KMS | Documented extension points only — deliberately not stubbed to look functional. |
| India eSign | Design only. Cannot be stubbed without falsely implying legal compliance. |
| Testcontainers integration tests | Dependencies declared; no container tests written (no Docker available). |
| PDF report export | HTML and JSON export are implemented; PDF export is not. |
| Grafana dashboards | Prometheus scrape config only. |

---

## 8. Test results

All figures below are from actual runs, not projections.

### Backend — 60 tests, all passing

```
AuditChainPersistenceTest          2 passed   database round trip
AuditIntegrityServiceTest          9 passed   hash chain
AuthorizationTest                 12 passed   attempts privilege escalation
DigitalSignatureAttackSuiteTest   12 passed   adversarial documents
RateLimiterTest                    6 passed   token bucket behaviour
SignAndVerifyTest                 10 passed   sign / verify / tamper
VisibleSignatureTest               5 passed   appearance does not weaken signing
TimestampHonestyTest               4 passed   absence never shown as valid
--------------------------------------------------------------------
Tests run: 60, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Note what the visible-signature tests can and cannot establish. They prove the signature
still verifies, the page count is unchanged, tampering is still caught, and the file grew
(so the appearance was not silently dropped). They cannot tell whether the block is
legible, correctly positioned, or clipped — so `VisibleSignaturePreview` renders the
signed page to PNG for a person to look at. That distinction between "asserted by a test"
and "checked by a human" is worth keeping explicit.

### Attack simulation suite — printed by the suite from observed results

```
  Valid PDF signature                          PASS
  Modified signed content                      DETECTED
  Signature corruption                         DETECTED
  Untrusted certificate                        DETECTED (amber)
  Expired certificate                          DETECTED
  Certificate outside validity window          DETECTED
  Wrong signing certificate                    DETECTED
  Unsigned document                            DETECTED
  Malformed document                           DETECTED
  Page appended via full rewrite               DETECTED
  Second signature preserves the first         PASS (2 valid signatures)
  Post-signature revision classified honestly  PASS
```

### Frontend — 23 tests, all passing

```
src/test/verdict.test.ts      18 passed
src/test/StatusChip.test.tsx   5 passed
---------------------------------------
Test Files  2 passed (2)
Tests      23 passed (23)
```

### End-to-end, against the live API

`scripts/demo-flow.ps1` was executed against a running backend. Real output:

```
Verdict VALID       → integrity INTACT, signature VALID, certificate VALID,
                      chain TRUSTED, revocation NOT_CHECKED, timestamp NOT_AVAILABLE
                      ByteRange [0, 1610, 34380, 779]

Verdict TAMPERED    → integrity MODIFIED, signature INVALID,
                      certificate VALID, chain TRUSTED
                      classification SIGNED_CONTENT_CHANGED, proven TRUE

Audit chain intact  → True (all records recomputed correctly)
```

### Four real defects found by running the system

All four were found because the system was actually executed rather than only compiled.
None would have failed a compile, and two would have passed a casual code review.

**1. X.500 name re-encoding broke PKIX path building.** The development PKI built issuer
names by re-parsing an RFC 2253 string, which can change the ASN.1 string types chosen per
attribute. The names were textually identical but encoded to different bytes, and PKIX
compares encoded names — so no trusted path could ever be built. Fixed by taking the issuer
name from its DER encoding.

**2. Timestamp precision broke the audit chain.** `Instant.now()` carries nanoseconds; a
SQL `TIMESTAMP` column stores microseconds. The value hashed was not the value read back,
so every record failed to recompute and the dashboard reported tampering that had not
happened. A control that cries wolf is worse than no control. Fixed by truncating to
milliseconds before hashing, and guarded by `AuditChainPersistenceTest`, which exercises a
real database round trip.

**3. Nonsensical signature algorithm name.** The verification report displayed
`SHA256withSHA256WITHRSA`. Bouncy Castle resolves the SignerInfo OID to a *complete*
algorithm name already, and the code was prefixing a digest onto it. Found by reading a
generated HTML report rather than by any test — a reminder that output nobody looks at is
output nobody checks. Now asserted in `SignAndVerifyTest`.

**4. Unauthenticated requests returned 403 instead of 401.** Spring Security's default
answer for an anonymous request to a protected endpoint is 403, which made "your session
expired" indistinguishable from "you lack permission". The visible symptom was an expired
session showing an opaque error on every screen instead of returning to the login page.
Fixed with an explicit `RestAuthenticationEntryPoint` (401) and `RestAccessDeniedHandler`
(403), plus a frontend interceptor that clears the session on 401 only — never on 403,
where signing in again would change nothing. `AuthorizationTest` now pins both.

---

## 9. Known limitations

**Not verified in this environment.** Docker is not installed on the machine this was
built on, so `docker-compose.yml` and both Dockerfiles have **never been executed**. They
are written carefully but must be treated as untested. The same applies to the CI workflow.

**Inherent limitations:**

- Without a trusted timestamp, the time of signing cannot be proven.
- The audit chain is tamper-*evident*, not tamper-*proof*. Full database write access
  defeats it.
- The audit append lock is per-JVM — correct for one instance, incorrect across several.
- Signing and verification load whole PDFs into memory (PDFBox requires random access).
- No encryption at rest; no token revocation.
- Authorisation is coarse: role plus document ownership, with no sharing model.
- A valid signature proves a document is unchanged. It says nothing about whether its
  contents are true.

---

## 10. How to demo

```bash
cd backend  && mvn spring-boot:run        # terminal 1
cd frontend && npm run dev                # terminal 2
```

Open http://localhost:5173, or run the scripted flow:

```bash
DOCUTRUST_DEMO_USER_PASSWORD='...' powershell -File scripts/demo-flow.ps1
```

A presenter's script with timings is in [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).

---

## 11. Interview talking points

1. **"Show me tamper detection."** Change a byte in a signed PDF, verify, and point out
   that the certificate is *still valid*. Then explain why: the digest over the
   `/ByteRange` no longer matches, and that is arithmetic, not heuristics.

2. **"Why is trust configured rather than read from the document?"** Because a forger
   controls the document *and* the chain inside it. Validating against the embedded chain
   would pass every self-signed forgery.

3. **"Why three verdicts?"** A cryptographically valid signature from an unknown signer is
   neither authentic nor forged. Collapsing that into green or red is wrong in both
   directions.

4. **"Why does timestamp say NOT_AVAILABLE?"** Because no TSA is configured and the system
   refuses to imply otherwise. This is the answer that demonstrates the engineering
   judgement behind the whole project.

5. **"Why is `SigningProvider` shaped like that?"** Because exposing a `PrivateKey` would
   permanently exclude HSM and KMS backends, which exist precisely so the key cannot be
   exported.

6. **"What broke while you built it?"** The two defects in section 8 — both real, both
   found by running the system, both now covered by tests. The audit chain one is the more
   interesting story, because the failure mode was a false alarm from a security control.

Full question-and-answer preparation is in [INTERVIEW_GUIDE.md](INTERVIEW_GUIDE.md).
