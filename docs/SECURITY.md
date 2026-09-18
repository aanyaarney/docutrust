# Security Controls

What is implemented, where it lives, and what it does not cover. Companion to
[THREAT_MODEL.md](THREAT_MODEL.md), which analyses attacks; this document describes
controls.

---

## Upload validation

`PdfUploadValidator` rejects an upload unless it passes every check:

| Check | Why |
|---|---|
| Non-empty, within size limit | Enforced at both the servlet container and the application layer. The container limit stops a huge body being buffered at all. |
| **Magic bytes** begin with `%PDF-` | The declared `Content-Type` is supplied by the client and can say anything. Only the file's own first bytes mean anything. |
| Structural parse succeeds | A file can start with `%PDF-` and still be unusable. Parsing at upload means signing does not fail later on a file that was never viable. |
| Not encrypted | An encrypted PDF cannot be signed; failing here gives a clear message instead of an obscure one later. |
| At least one page | Guards against degenerate documents. |

**Filename sanitisation** strips directory components (both separator styles), removes
everything outside `[A-Za-z0-9._ -]`, strips leading dots, caps length at 200 characters,
and enforces a `.pdf` extension. A filename is attacker-controlled text that reaches
storage keys, HTTP headers and the UI — `../../etc/passwd` and embedded newlines must not
survive.

Storage keys are **composed by the application** (`documents/{uuid}/v{n}.pdf`), never taken
from user input. `FilesystemDocumentStorage` additionally verifies every resolved path
stays inside the storage root, as defence in depth.

---

## Authentication and authorisation

- **Passwords**: BCrypt, strength 12 (`SecurityConfiguration.passwordEncoder`). BCrypt is
  deliberately slow and salts every hash, which is what makes offline cracking of a leaked
  table expensive. No custom hashing anywhere.
- **Tokens**: JWT, HS256. The secret must be at least 32 bytes or the application refuses
  to start. Outside the `local` profile a missing secret is a startup failure rather than
  a silently generated one.
- **Login responses** are identical for unknown email, wrong password and disabled
  account. A dummy BCrypt comparison runs when no user exists, so a non-existent account
  is not measurably faster to reject — otherwise timing alone enumerates valid addresses.
- **Roles**: `USER`, `VERIFIER`, `ADMIN`, enforced server-side via
  `@EnableMethodSecurity` and path rules. The frontend route guard is a usability
  affordance and is documented as such in `App.tsx` — it protects nothing.

---

## CSRF: why it is disabled

CSRF attacks work because browsers attach **ambient credentials** — cookies — to
cross-site requests automatically. The attacking page never needs to read anything; it
just causes a request, and the browser supplies the session.

DocuTrust authenticates with a bearer token in an `Authorization` header. A browser never
attaches that automatically. An attacking page would first have to *read* the token, and
same-origin policy prevents it. With no ambient credential there is no CSRF vector, so
token synchronisation would add machinery without adding protection.

**This reasoning depends entirely on the token never being stored in a cookie.** If
authentication moves to cookies, CSRF protection must be re-enabled in the same change.
That condition is recorded in the `SecurityConfiguration` javadoc so it is visible to
whoever makes that change.

---

## HTTP security headers

Set by Spring Security on API responses and by nginx on the frontend:

| Header | Purpose |
|---|---|
| `X-Content-Type-Options: nosniff` | Stops the browser second-guessing content types |
| `X-Frame-Options: DENY` / `frame-ancestors 'none'` | Prevents clickjacking |
| `Strict-Transport-Security` | Forces HTTPS on subsequent visits |
| `Referrer-Policy: strict-origin-when-cross-origin` | Limits URL leakage to third parties |
| `Content-Security-Policy` | Restricts scripts to same-origin |

The CSP permits `'unsafe-inline'` for **styles only**, which Emotion requires to inject
MUI's styles at runtime. Scripts remain same-origin. This is a real if modest weakening
and is stated rather than hidden.

---

## CORS

Explicit origins only (`docutrust.cors.allowed-origins`), never a wildcard.
`allowCredentials` is `false` because authentication is header-based. In development the
Vite proxy routes `/api` through the same origin, so CORS is not exercised at all locally.

---

## Logging policy

Never logged, anywhere:

- private keys or any key material
- keystore, truststore or account passwords
- JWTs, `Authorization` header values, or any bearer token
- document contents

Implemented by: `UserEntity.toString()` omitting the password hash; the JWT filter logging
only an exception class name; `GlobalExceptionHandler` authoring client messages rather
than forwarding exception text; Hibernate SQL logging left off; metric labels excluding
filenames (which both explodes cardinality and leaks potentially confidential names into a
metrics backend).

Every request carries a correlation ID (`CorrelationIdFilter`) that appears in logs, audit
records and error responses. A client-supplied `X-Correlation-Id` is accepted for
cross-service tracing but is length-capped and stripped to `[A-Za-z0-9._-]`, because an
unsanitised header containing newlines can forge whole log lines.

---

## Error responses

One shape everywhere:

```json
{
  "code": "DOCUMENT_NOT_FOUND",
  "message": "The requested document does not exist, or you do not have access to it.",
  "correlationId": "a1b2c3d4e5f60718",
  "timestamp": "2026-09-16T18:38:33Z"
}
```

Messages are written for the handler, not taken from exception text — an exception message
may name a file path, a SQL fragment or a keystore location. Full detail including stack
traces is logged server-side against the same correlation ID. The catch-all handler returns
a deliberately uninformative message, since an unexpected exception is exactly where
internal detail is most likely to leak.

"Not found" and "not yours" return the **same** error, so document identifiers cannot be
enumerated by distinguishing the two.

---

## SQL injection

All database access goes through Spring Data JPA derived queries and JPQL. There is no
string-concatenated SQL and no native query taking user input anywhere in the codebase.

---

## Secrets

- No credential appears in source. All come from the environment; `.env.example` contains
  only `CHANGE_ME` placeholders.
- `.gitignore` blocks `*.p12`, `*.pfx`, `*.jks`, `*.key`, `*.pem`, `*.der`, `*.crt`,
  `.env`, and `pki-local/`.
- Demo passwords are generated with `SecureRandom` at startup and printed once, only under
  the `local` profile.
- Key material is mounted read-only into the backend container and never baked into an
  image.

---

## Container hardening

Both images are multi-stage, so the runtime image carries no compiler, build tooling or
source. The backend runs as an unprivileged user (`docutrust`), not root. Heap is sized
with `-XX:MaxRAMPercentage` so the JVM respects the container limit rather than the host's
memory. Health checks are defined for orchestration.

**These images have not been built or run** — Docker is not installed in the environment
this was developed in. Treat them as untested.

---

## Rate limiting

Implemented with token buckets (`RateLimitFilter`, `RateLimiter`, `TokenBucket`).

| Endpoint | Keyed by | Default |
|---|---|---|
| `POST /auth/login` | source address | 10/minute, burst 10 |
| `POST /verification`, `POST /documents/{id}/sign` | authenticated account | 30/minute, burst 15 |

Everything else is unlimited. Listing documents is cheap, and a limit that fires during
ordinary use trains people to ignore it.

**Why two different keys.** Credential stuffing spreads guesses *across* accounts
specifically to evade per-account limits, so the authentication limit has to bind to the
thing an attacker must actually spend — network origin. Signing and verification are the
opposite case: the work is attributable to an account, so the limit belongs there.

**Why a token bucket rather than a fixed window.** A fixed window permits a double burst
straddling the boundary — 60 requests at 11:59:59 and 60 more at 12:00:00 — precisely when
an attacker is pushing hardest. A token bucket refills continuously and has no boundary to
straddle.

Refusals return `429` with a `Retry-After` header and the standard error shape. The
tracked-key map is capped so that an attacker rotating source addresses cannot turn the
denial-of-service control into a denial-of-service vector.

**Limitation.** State is in-memory and therefore per-instance. Across several instances the
effective limit multiplies by the instance count; a shared store (Redis) or an edge-level
limit is required before horizontal scaling.

`X-Forwarded-For` is honoured because the application is expected to sit behind a reverse
proxy. That header is client-controlled and trivially spoofed when no proxy strips it, so a
deployment exposing the application directly must disable that branch.

---

## Dependency and container scanning

The CI workflow runs `mvn dependency-check` and `npm audit`, and Trivy against built
images. No suppression file is committed, so a new advisory surfaces rather than being
silently ignored.

---

## Reporting a vulnerability

This is a demonstration project and is not deployed. If you find an issue in the code,
open an issue describing the problem and its impact.
