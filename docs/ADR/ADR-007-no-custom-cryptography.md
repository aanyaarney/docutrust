# ADR-007: No Custom Cryptographic Algorithms

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust depends on RSA and ECDSA signatures, SHA-256 digests, ASN.1 encoding, CMS
SignedData construction and parsing, X.509 handling, and PKIX path validation. Every one
of these could, in principle, be implemented from its specification.

## Decision

Implement **none** of them. All cryptographic primitives and encodings come from:

- **Bouncy Castle 1.80** — CMS SignedData, ASN.1, certificate generation, PKIX helpers
- **Apache PDFBox 3.0.7** — PDF parsing and incremental-update signing mechanics
- **The JDK** — `MessageDigest`, `Signature`, `KeyStore`, `CertPathBuilder`, `SecureRandom`

The repository contains no implementation of a hash function, a signature algorithm, an
ASN.1 encoder, or a certificate parser. Code under `com.docutrust` composes these libraries
and interprets their results.

Randomness for security purposes always comes from `SecureRandom` — certificate serial
numbers, verification identifiers, JWT identifiers, generated passwords.
`java.util.Random` is never used for any of these.

## Alternatives considered

**Implement primitives for educational value.** Rejected. Cryptographic code fails in ways
ordinary code does not: timing side channels, padding oracles, biased nonces, malleable
encodings, non-constant-time comparison. None of these cause a test to fail. An
implementation that passes its own tests is not evidence of correctness — it is evidence
that the author has not yet found the bug. A correct-looking RSA implementation that leaks
key bits through timing is indistinguishable from a good one until somebody measures it.

**Write only the "simple" parts, such as ASN.1 encoding.** Rejected. ASN.1 is a notorious
source of vulnerabilities precisely because it appears simple. Parser differentials, where
two implementations disagree about the same bytes, have produced real signature-bypass
vulnerabilities.

**Use only the JDK, avoiding Bouncy Castle.** Rejected. The JDK has no public CMS
SignedData API, which PAdES requires. Building CMS by hand would reintroduce exactly the
hand-rolled ASN.1 this decision rules out.

## Consequences

**Positive**
- The security-critical surface is code reviewed by cryptographers and hardened by years
  of real CVEs found and fixed.
- Dependency scanning provides a route to learning about vulnerabilities; hand-written
  cryptography has no advisory feed.
- DocuTrust's own code stays focused on what is genuinely its problem: orchestration,
  trust evaluation, and honest reporting of uncertainty.

**Negative**
- Behaviour is constrained by what the libraries expose. One concrete instance encountered
  during development: Bouncy Castle's certificate-based CMS verifier also rejects
  signatures whose claimed signing time falls outside the certificate's validity window,
  conflating "is the signature mathematically sound" with "was the certificate valid then".
  Since DocuTrust must report those independently, it verifies against the certificate's
  public key and evaluates validity separately — a workaround documented at the call site
  in `VerificationService`.
- Library upgrades require re-testing the cryptographic paths.
