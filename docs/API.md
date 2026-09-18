# API Reference

Base path: `/api/v1`. Interactive documentation (springdoc/OpenAPI) is served at
http://localhost:8080/swagger-ui.html while the backend is running.

All endpoints except `POST /auth/login` and the public actuator endpoints require an
`Authorization: Bearer <token>` header.

---

## Authentication

### `POST /auth/login`

```json
{ "email": "demo@docutrust.local", "password": "..." }
```

**200**

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresInSeconds": 3600,
  "userId": "…", "email": "demo@docutrust.local",
  "displayName": "Demo User", "role": "USER"
}
```

**401** — returned identically for unknown email, wrong password and disabled account, so
that valid addresses cannot be enumerated.

### `GET /auth/me`

Describes the authenticated caller. Carries no credential material.

---

## Documents

| Method | Path | Role | Purpose |
|---|---|---|---|
| `POST` | `/documents` | USER, ADMIN | Upload a PDF (multipart, field `file`) |
| `GET` | `/documents` | any | List documents owned by the caller |
| `GET` | `/documents/{id}` | owner | Metadata |
| `POST` | `/documents/{id}/sign` | USER, ADMIN | Apply a PAdES signature |
| `GET` | `/documents/{id}/download` | owner | Download (`?version=N`, default latest) |
| `GET` | `/documents/{id}/versions` | owner | Version history |
| `GET` | `/documents/{id}/signatures` | owner | Recorded signatures |
| `GET` | `/documents/{id}/audit` | owner | Audit history for this document |

### `POST /documents` — 201

```json
{
  "id": "7407dfff-d629-4f68-82e9-99ab23c97a05",
  "fileName": "employment-contract.pdf",
  "sizeBytes": 1262,
  "sha256": "ec0d160c8aa7cc7fd9db6a9c2ad65778d6717ed08abe5e189d23f481a14018d1",
  "pageCount": 1,
  "signatureState": "UNSIGNED",
  "uploadedAt": "2026-09-16T13:08:33Z"
}
```

Uploads are validated by magic bytes and a structural parse, not the declared
`Content-Type`. Filenames are sanitised before storage.

### `POST /documents/{id}/sign`

```json
{ "reason": "I approve this agreement", "location": "Bengaluru, IN",
  "signerDisplayName": "Demo Signer" }
```

**200**

```json
{
  "documentId": "…",
  "signerCommonName": "Demo Signer",
  "certificateSubject": "C=IN,OU=Demonstration,O=DocuTrust,CN=Demo Signer",
  "certificateIssuer": "C=IN,OU=Development PKI,O=DocuTrust,CN=DocuTrust Development Issuing CA",
  "certificateSerialNumber": "3F8E4B23DD41AF2DDDDE19523FF942A8FFA4C124",
  "signatureAlgorithm": "SHA256withRSA",
  "digestAlgorithm": "SHA-256",
  "signatureFormat": "PAdES-B-B",
  "providerName": "PKCS12",
  "signingTime": "2026-09-16T13:08:34Z",
  "signedSizeBytes": 35159
}
```

Signing always targets the **latest** version, which is what allows multiple signatures via
incremental update without invalidating earlier ones.

---

## Verification

### `POST /verification`

Multipart, field `file`; optional `documentId`. Accepts **any** PDF, including documents
DocuTrust never issued. Verification reads only the file and the configured trust anchors —
no database record influences the outcome.

**200 — valid document**

```json
{
  "verificationId": "VER-A1B2C3D4E5F6",
  "verdict": "VALID",
  "headline": "Authentic document",
  "explanation": "The digital signature verifies, the signed content is unchanged, and …",
  "documentSha256": "ec0d160c…",
  "fileName": "signed.pdf",
  "pageCount": 1,
  "fileSizeBytes": 35159,
  "verifiedAt": "2026-09-16T13:08:35Z",
  "signatures": [
    {
      "index": 0,
      "signerName": "Demo Signer",
      "reason": "I approve this agreement",
      "location": "Bengaluru, IN",
      "claimedSigningTime": "2026-09-16T13:08:34Z",
      "integrity": "INTACT",
      "signature": "VALID",
      "timestamp": "NOT_AVAILABLE",
      "timestampAuthority": null,
      "timestampAttestedTime": null,
      "signatureFormat": "PAdES (ETSI.CAdES.detached)",
      "digestAlgorithm": "SHA256",
      "signatureAlgorithm": "SHA256withRSA",
      "byteRange": [0, 1610, 34380, 779],
      "coversEntireDocument": true,
      "verdict": "VALID",
      "certificate": {
        "status": "VALID",
        "validPeriod": true,
        "chainStatus": "TRUSTED",
        "revocationStatus": "NOT_CHECKED",
        "details": {
          "subject": "C=IN,OU=Demonstration,O=DocuTrust,CN=Demo Signer",
          "issuer":  "C=IN,OU=Development PKI,O=DocuTrust,CN=DocuTrust Development Issuing CA",
          "serialNumber": "3F8E4B23…",
          "validFrom": "2026-09-15T13:07:04Z",
          "validUntil": "2028-09-15T13:07:04Z",
          "publicKeyAlgorithm": "RSA",
          "keySizeBits": 2048,
          "signatureAlgorithm": "SHA256WITHRSA",
          "sha256Fingerprint": "42d236cc…",
          "keyUsages": ["digitalSignature", "nonRepudiation"],
          "extendedKeyUsages": ["1.3.6.1.5.5.7.3.36"],
          "selfSigned": false,
          "version": 3
        },
        "chain": [ /* leaf-first */ ],
        "failureReason": null
      },
      "tamperAnalysis": {
        "tampered": false,
        "modificationType": "NONE",
        "explanation": "No modification detected. …",
        "affectedRevision": null,
        "cryptographicallyProven": true
      }
    }
  ]
}
```

**200 — tampered document** (abridged)

```json
{
  "verdict": "TAMPERED",
  "headline": "Tampering detected",
  "signatures": [{
    "integrity": "MODIFIED",
    "signature": "INVALID",
    "certificate": { "status": "VALID", "chainStatus": "TRUSTED" },
    "tamperAnalysis": {
      "tampered": true,
      "modificationType": "SIGNED_CONTENT_CHANGED",
      "cryptographicallyProven": true
    }
  }]
}
```

Note that the certificate remains `VALID` and the chain `TRUSTED`. The certificate did not
change; the document did.

### `GET /verification/{verificationId}`

Returns a previously recorded outcome. **404** if unknown.

### `GET /verification/{verificationId}/report?format=html|json`

Downloads the full stored report. `html` (the default) returns a self-contained document
with inline styles and no external requests; `json` returns the machine-readable report.
Both are served as attachments.

A stored report records what verification concluded at that moment. It is deliberately not
a substitute for verifying again — trust anchors and revocation state change, so the same
document can legitimately produce a different verdict later.

**404** if no report is stored for that identifier.

---

## Certificates

### `GET /certificates`

Describes the configured signing chain and trust anchors. Public certificate data only —
no private key material is reachable through any endpoint.

```json
{
  "signingChain": [ /* leaf-first CertificateDetails */ ],
  "trustAnchors": [ /* CertificateDetails */ ],
  "providerName": "PKCS12",
  "description": "Ephemeral development PKI (regenerated at each startup)",
  "developmentPki": true
}
```

### `GET /certificates/signer`

The signer certificate alone.

---

## Dashboard and audit

| Method | Path | Role |
|---|---|---|
| `GET` | `/dashboard/summary` | any |
| `GET` | `/admin/audit/integrity` | ADMIN |
| `GET` | `/admin/audit/recent` | ADMIN |

`/admin/audit/integrity` recomputes the entire hash chain and reports the first record that
fails, if any.

---

## Status values

These unions are the contract. `NOT_CHECKED` and `NOT_AVAILABLE` are distinct from success
values and must never be rendered as though they were positive results.

| Field | Values |
|---|---|
| `verdict` | `VALID`, `VALID_UNTRUSTED`, `TAMPERED`, `INVALID`, `UNSIGNED`, `ERROR` |
| `integrity` | `INTACT`, `MODIFIED`, `UNKNOWN` |
| `signature` | `VALID`, `INVALID`, `CORRUPTED`, `UNKNOWN` |
| `certificate.status` | `VALID`, `EXPIRED`, `NOT_YET_VALID`, `REVOKED`, `INVALID`, `UNKNOWN` |
| `chainStatus` | `TRUSTED`, `UNTRUSTED`, `INCOMPLETE`, `INVALID`, `NOT_CHECKED` |
| `revocationStatus` | `GOOD`, `REVOKED`, `UNKNOWN`, `NOT_CHECKED`, `ERROR` |
| `timestamp` | `VALID`, `INVALID`, `NOT_AVAILABLE`, `NOT_CHECKED` |
| `modificationType` | `NONE`, `SIGNED_CONTENT_CHANGED`, `POST_SIGNATURE_INCREMENTAL_UPDATE`, `SIGNATURE_CORRUPTED`, `UNSUPPORTED_CHANGE`, `UNKNOWN` |

---

## Errors

Every error uses one shape:

```json
{
  "code": "DOCUMENT_NOT_FOUND",
  "message": "The requested document does not exist, or you do not have access to it.",
  "correlationId": "a1b2c3d4e5f60718",
  "timestamp": "2026-09-16T13:08:33Z"
}
```

| Code | Status | Meaning |
|---|---|---|
| `AUTHENTICATION_FAILED` | 401 | Credentials rejected |
| `ACCESS_DENIED` | 403 | Authenticated but not permitted |
| `DOCUMENT_NOT_FOUND` | 404 | Unknown document, or not the caller's |
| `UNSUPPORTED_DOCUMENT` | 400 | Not a valid PDF, encrypted, or empty |
| `VALIDATION_FAILED` | 400 | Request body failed validation |
| `FILE_TOO_LARGE` | 413 | Exceeds the configured limit |
| `CERTIFICATE_VALIDATION_FAILED` | 422 | Certificate could not be evaluated |
| `SIGNING_FAILED` | 500 | Signature could not be produced |
| `STORAGE_ERROR` | 500 | Document storage unavailable |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests; a `Retry-After` header gives the wait in seconds |
| `INTERNAL_ERROR` | 500 | Unexpected failure |

Responses never contain stack traces, file paths, SQL or configuration. That detail is
logged server-side against the same `correlationId`.

"Not found" and "not yours" deliberately return the same error so document identifiers
cannot be enumerated.
