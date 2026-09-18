# Cryptography in DocuTrust

Written for someone who knows how to program but has not worked with PKI. It explains
what each mechanism does, why it is needed, and what it does *not* prove.

---

## 1. Hashing is not encryption, and signing is neither

Three things are routinely confused. They solve different problems.

| Mechanism | Answers | Reversible? | Needs a key? |
|---|---|---|---|
| **Hashing** (SHA-256) | "Did these bytes change?" | No — one-way | No |
| **Encryption** | "Can an eavesdropper read this?" | Yes, with the key | Yes |
| **Digital signature** | "Who produced this, and has it changed?" | n/a | Yes (private to sign, public to verify) |

DocuTrust does **no encryption**. A signed document is fully readable by anyone. That is
intentional: the goal is authenticity and integrity, not confidentiality. A signed
contract you cannot read would be useless.

---

## 2. SHA-256

A hash function maps any input to a fixed-size output — 256 bits for SHA-256 — with three
properties that matter here:

- **Deterministic** — the same input always gives the same digest.
- **Avalanche** — changing one bit changes roughly half the output bits. There is no
  "close" digest; a one-character edit produces something entirely unrelated.
- **Collision resistant** — nobody knows how to construct two different inputs with the
  same SHA-256 digest.

That last property is why SHA-1 is deprecated for signatures. Once collisions became
practical, an attacker could prepare two documents with the same digest, get an innocuous
one signed, and attach that signature to the other. The signature would verify perfectly
on a document its signer never approved.

```
"Salary: INR 800,000"  →  SHA-256  →  b4a9…0f2e
"Salary: INR 900,000"  →  SHA-256  →  7c31…dd84      ← completely different
```

### Why a hash alone is not enough

A digest proves a document has not changed **only if you already have a trustworthy copy
of the digest**. If an attacker can alter the document, they can usually alter a digest
published alongside it and recompute it to match.

Hashing answers "did this change since I recorded the digest?" It cannot answer "who
vouched for this?" That requires a key.

---

## 3. Public-key cryptography

A key pair consists of two mathematically related keys:

- the **private key**, kept secret by its owner;
- the **public key**, which can be given to anyone.

For signatures the relationship is: something the private key produces can be checked with
the public key, and *only* that matching public key will check out. Deriving the private
key from the public one is computationally infeasible.

```
Signing                          Verification
-------                          ------------
document                         document
   │                                │
   ▼                                ▼
SHA-256 digest                   SHA-256 digest (recomputed)
   │                                │
   ▼                                ▼
sign with PRIVATE key  ───────►  check with PUBLIC key
   │                                │
   ▼                                ▼
digital signature                VALID / INVALID
```

Two facts fall out of this:

- **Only the private key holder could have produced the signature.** That is the identity
  claim.
- **The digest is covered by the signature.** If the document changes, the recomputed
  digest differs from the signed one, and verification fails. That is the integrity claim.

DocuTrust uses RSA 2048-bit with SHA-256 (`SHA256withRSA`) by default and supports ECDSA
(`SHA256withECDSA`). ECDSA achieves comparable security with much smaller keys, which is
why it dominates newer deployments.

---

## 4. X.509 certificates and why they are necessary

A public key on its own is just a number. Nothing about it says who owns it. If an
attacker hands you their public key claiming it belongs to Northwind Textiles, signatures
they make will verify against it perfectly — they are internally consistent forgeries.

An **X.509 certificate** solves this by binding a public key to an identity, with that
binding signed by a **Certificate Authority (CA)**:

```
Certificate
├── Subject:        CN=Demo Signer, O=DocuTrust, C=IN     ← who owns the key
├── Public Key:     RSA 2048 bits                          ← the key itself
├── Issuer:         CN=DocuTrust Development Issuing CA    ← who vouches
├── Validity:       2026-09-15 → 2028-09-15
├── Serial Number:  F514E8FF…
├── Key Usage:      digitalSignature, nonRepudiation
└── CA's signature over all of the above
```

The CA's signature is the point. It means an authority has asserted that this public key
belongs to this subject — and that assertion is itself verifiable.

### The certificate chain

You do not have to trust every CA individually. Certificates chain:

```
Root CA  (self-signed, in the trust store)
   │  signs
   ▼
Intermediate / Issuing CA
   │  signs
   ▼
Signer certificate  ("Demo Signer")
```

Verification walks this chain upward, checking at each step that the certificate really
was signed by the key of the one above it, until it reaches a certificate that is already
trusted. That final certificate is the **trust anchor**.

Intermediates exist so the root's private key can stay offline in a vault. If an
intermediate is compromised, it can be revoked without invalidating every certificate the
root ever issued.

### Trust must be configured, not inherited from the document

This is the single most important design decision in DocuTrust.

A submitted PDF embeds the signer's certificate chain. Validating a signature against the
chain shipped *inside the same file* is circular and worthless: an attacker who forges a
document also chooses the chain they embed in it, so every self-signed forgery would pass.

DocuTrust therefore loads trust anchors from a configured trust store, out of band.
Certificates found inside a document are treated as **claims to be checked against** those
anchors, never as anchors themselves.

The consequence is visible in the product: a well-formed self-signed signature verifies
cryptographically and is reported **VALID_UNTRUSTED** (amber), not VALID. That is the
correct answer — real signature, unproven signer.

---

## 5. PAdES: signatures inside a PDF

**PAdES** (PDF Advanced Electronic Signatures, ETSI EN 319 142) specifies how a CMS
signature is embedded in a PDF so that any conformant reader can verify it.

Signing performs an **incremental update**: the original bytes are never rewritten, and a
signature dictionary is appended. That dictionary contains a `/Contents` entry — a
reserved block of zero bytes that will hold the signature — and a `/ByteRange` array
naming the spans of the file the signature covers:

```
[ ... PDF content ... ][ /Contents hole ][ ... PDF content ... ]
|<------- signed ----->|   not signed    |<------- signed ----->|
 offset 0    len 1610                     offset 34380  len 779

/ByteRange [0 1610 34380 779]
```

Everything except the hole is covered. The digest is computed over the concatenation of
those two spans, signed, and the resulting CMS structure written into the hole.

This is what makes tamper detection cryptographic rather than heuristic. There is no
comparison against a stored original and no guesswork — changing any byte in the covered
range changes the digest, and the signature stops verifying.

### Baseline levels

| Level | Adds | Answers |
|---|---|---|
| **B-B** | Basic signature | Who signed, and has it changed? |
| B-T | Trusted timestamp | *When* was it signed? |
| B-LT | Embedded revocation data | Was the certificate valid at signing time, checkable later? |
| B-LTA | Archival timestamps | Still verifiable decades from now? |

DocuTrust implements **B-B**. The architecture accommodates the higher levels; they are
not implemented, and the product says so rather than implying otherwise.

### Required signed attributes

Three attributes are covered by the signature itself:

- **content-type** and **message-digest** — standard CMS, added by Bouncy Castle.
- **signing-certificate-v2** (RFC 5035) — **required by PAdES**. It carries a hash of the
  signer certificate *inside the signed attributes*, binding the signature to one specific
  certificate. Without it, an attacker could substitute a different certificate carrying
  the same public key and change the apparent identity of the signer.

### Multiple signatures

Because signing is an incremental update, a second signature appends to the file without
rewriting earlier bytes. The first signature's byte range still digests to the same value,
so **both signatures remain valid**:

```
Revision 1:  document                          ← Employee's signature covers this
Revision 2:  document + signature 1            ← Manager's signature covers this
```

Rewriting the file instead of appending would silently destroy every existing signature.
The attack suite asserts that a second signature leaves the first valid.

Note the honest nuance: after a second signature, the first no longer covers the end of
the file. DocuTrust surfaces this as `POST_SIGNATURE_INCREMENTAL_UPDATE` and explicitly
marks it **not** cryptographically proven tampering, because appending is exactly how
legitimate counter-signatures and permitted form-filling work.

---

## 6. Timestamps

A signature contains a `signing-time` attribute. **The signer chooses that value.** It can
say anything.

To prove *when* something was signed you need a third party: an **RFC 3161 Timestamp
Authority**. You send it a hash of your signature; it returns a token signed with its own
key attesting that the hash existed at that moment.

This matters because certificates expire. Without a trusted timestamp, a verifier cannot
distinguish:

- a signature made while the certificate was valid (legitimate — expiry does not
  retroactively forge it), from
- a signature made after expiry using a key that should have been retired.

DocuTrust has no TSA configured and reports timestamp status as `NOT_AVAILABLE`. It never
presents the signer's claimed time as evidence.

---

## 7. Revocation

A certificate can be valid by date yet revoked — key compromise, employee departure,
issuance error. Two mechanisms report this:

- **CRL** — the CA publishes a signed list of revoked serial numbers. Simple; can be large
  and stale between publications.
- **OCSP** — the verifier queries a responder about one certificate. Fresher; requires the
  responder to be reachable and leaks which certificate you are checking.

DocuTrust models five outcomes and keeps them distinct:

```
GOOD         a responder was asked and said "not revoked"
REVOKED      a responder was asked and said "revoked"
UNKNOWN      asked, but the responder could not answer authoritatively
NOT_CHECKED  no check was attempted
ERROR        a check was attempted and failed technically
```

Only `GOOD` is positive evidence. The development configuration performs no checks and
reports `NOT_CHECKED` — never `GOOD`. Reporting "we did not look" as "all clear" is
precisely the false assurance this system exists to avoid.

---

## 8. Why signing keys belong in an HSM

In this build the private key lives in a PKCS#12 file and is loaded into process memory.
That is acceptable for a local demonstration and unacceptable for signing of consequence:
anyone who reads the file and its password can sign as you, forever, undetectably.

A **Hardware Security Module** or cloud KMS inverts this. The key is generated inside the
device and never leaves it. You send data in and get a signature back; there is no API
that exports the key. Compromising the server no longer means compromising the key — an
attacker can sign only while they retain access, and every use can be logged
independently.

`SigningProvider` is deliberately shaped for this: it takes content and returns a
signature, and never exposes a `PrivateKey`. A design built around retrieving the key
would make HSM and KMS providers impossible to implement without weakening them. See
[KMS_INTEGRATION.md](KMS_INTEGRATION.md).

---

## 9. What DocuTrust does not implement

No cryptographic primitive in this repository is hand-written. RSA, ECDSA, SHA-256, ASN.1
encoding, CMS/PKCS#7 construction, X.509 parsing and PKIX path validation all come from
Bouncy Castle, Apache PDFBox, and the JDK.

This is not laziness. Cryptographic implementations fail in ways ordinary code does not:
timing side channels, padding oracles, biased nonces, malleable encodings. These libraries
have had years of expert scrutiny and real CVEs found and fixed. A hand-rolled
implementation that passes its own tests is not evidence of correctness — it is evidence
that the author has not yet found the bug. See
[ADR-007](ADR/ADR-007-no-custom-cryptography.md).

---

## 10. Generating a development PKI

`make generate-dev-cert` writes a three-tier PKI to `./pki-local` (gitignored) using
Bouncy Castle, because OpenSSL is not present on a default Windows install.

The equivalent OpenSSL sequence, for reference:

```bash
# Root CA
openssl req -x509 -newkey rsa:3072 -keyout root.key -out root.crt \
  -days 3650 -nodes -subj "/CN=DocuTrust Development Root CA/O=DocuTrust/C=IN"

# Intermediate, signed by the root
openssl req -newkey rsa:3072 -keyout inter.key -out inter.csr -nodes \
  -subj "/CN=DocuTrust Development Issuing CA/O=DocuTrust/C=IN"
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial \
  -out inter.crt -days 1825 -extfile <(echo "basicConstraints=critical,CA:TRUE")

# Signer, signed by the intermediate
openssl req -newkey rsa:2048 -keyout signer.key -out signer.csr -nodes \
  -subj "/CN=Demo Signer/O=DocuTrust/C=IN"
openssl x509 -req -in signer.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
  -out signer.crt -days 730 \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n")

# Bundle into PKCS#12
openssl pkcs12 -export -out signer.p12 -inkey signer.key -in signer.crt \
  -certfile <(cat inter.crt root.crt)
```

**Never commit any of these files.** `.gitignore` blocks `*.p12`, `*.key`, `*.pem` and
`pki-local/`.
