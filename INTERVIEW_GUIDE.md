# Interview Guide

Answers to the questions this project invites. Each gives a short answer you could say out
loud, then the detail behind it.

The most valuable answers here are the ones about what the system *cannot* do. Being able
to state a limitation precisely is what separates someone who integrated a library from
someone who understands the problem.

---

## Hashing and digests

### Why SHA-256?

**Short answer.** It is collision resistant, fast, and the PAdES baseline default. SHA-1
is broken for signatures and MD5 has been broken for twenty years.

**Detail.** The property that matters for signatures is *collision resistance* — the
infeasibility of finding two different inputs with the same digest. Once SHA-1 collisions
became practical, an attacker could prepare two documents with the same digest, get an
innocuous one signed, and attach that signature to the other. The signature would verify
perfectly on a document its signer never approved. SHA-256 has no known practical collision
attack. SHA-384 or SHA-512 would also be fine; SHA-256 is the interoperable default.

### Why doesn't hashing alone prove who signed something?

**Short answer.** A hash proves the bytes did not change. It says nothing about who
computed it, and anyone can compute one.

**Detail.** A digest is only useful if you already have a trustworthy copy of it. If an
attacker can alter the document, they can usually alter a digest published next to it and
recompute it to match. Hashing answers "did this change since I recorded the digest?" It
cannot answer "who vouched for this?" That requires something only one party can do —
a private key.

---

## Public-key cryptography

### What does the private key do? What does the public key do?

**Short answer.** The private key produces the signature; the public key checks it. Only
the private key can create a signature that its matching public key accepts.

**Detail.** The signer computes a digest of the document and transforms it with the private
key. A verifier recomputes the digest from the document and uses the public key to check
that the signature corresponds. Two conclusions follow: only the private key holder could
have produced it (identity), and if the document changed, the recomputed digest differs and
verification fails (integrity).

Note this is *not* "encrypting with the private key". That description is a common
simplification and is misleading — modern signature schemes like RSA-PSS and ECDSA are not
encryption run backwards.

### What is the difference between signing and encryption?

Encryption provides **confidentiality** — it stops people reading. Signing provides
**authenticity and integrity** — it proves origin and detects change. DocuTrust does no
encryption at all: a signed document is fully readable by anyone. That is intentional. A
signed contract you could not read would be useless.

---

## Certificates and PKI

### Why X.509? Why not just share public keys?

**Short answer.** A bare public key carries no identity. A certificate binds a key to a
name, and that binding is signed by an authority.

**Detail.** If an attacker hands you their public key claiming it belongs to Northwind
Textiles, every signature they make verifies against it perfectly. They are internally
consistent forgeries. X.509 solves this by having a Certificate Authority sign a structure
containing the public key, the subject's identity, a validity window, and constraints such
as key usage. You verify the CA's signature, so you are trusting the CA's assertion rather
than the attacker's claim.

### What is a CA? What is a certificate chain?

A **Certificate Authority** vouches for the binding between a key and an identity by
signing certificates. A **chain** is the path from a signer's certificate up through any
intermediates to a root:

```
Root CA (self-signed, in the trust store)
   → Intermediate CA
      → Signer certificate
```

Verification checks at each step that a certificate really was signed by the key of the one
above it, until reaching a certificate already trusted — the **trust anchor**.

Intermediates exist so the root's private key can stay offline in a vault. If an
intermediate is compromised it can be revoked without invalidating everything the root ever
issued.

### Why does DocuTrust refuse to trust the chain inside the document?

**Short answer.** Because the forger chooses that chain too.

**Detail.** This is the single most important design decision in the project. A submitted
PDF embeds the signer's chain. Validating a signature against the chain shipped inside the
same file is circular: an attacker who forges a document also picks the chain they embed,
so every self-signed forgery would pass.

DocuTrust loads trust anchors from a configured trust store, out of band, and treats
embedded certificates as claims to check *against* those anchors. The visible consequence
is the amber verdict: a well-formed self-signed signature is reported `VALID_UNTRUSTED` —
real signature, unproven signer.

---

## PAdES and PDF signatures

### What is PAdES?

PDF Advanced Electronic Signatures (ETSI EN 319 142) — the standard for embedding a CMS
signature in a PDF so any conformant reader can verify it. DocuTrust implements Baseline-B,
the level that answers "who signed this and has it changed". Higher levels add timestamps
(B-T), embedded revocation data (B-LT), and archival timestamps (B-LTA).

### How does modifying one byte invalidate the signature?

**Short answer.** The signature covers a declared byte range, and SHA-256 has no notion of
"close".

**Detail.** The signature dictionary declares a `/ByteRange` covering the whole file except
the hole reserved for the signature itself:

```
[ ... PDF content ... ][ signature hole ][ ... PDF content ... ]
|<------- signed ----->|   not signed    |<------- signed ----->|
```

The digest is computed over the concatenation of those two spans. Because of the avalanche
property, changing one bit changes roughly half the digest bits. The recomputed digest then
does not match the digest sealed inside the signed attributes, and verification fails.

That is proof, not inference — which is also why DocuTrust reports *that* content changed
but never claims to know *which words* changed. Establishing that would need the original,
which a verifier does not have.

### How do multiple PDF signatures work?

Signing performs an **incremental update**: earlier bytes are never rewritten, and the new
signature is appended. The first signature's byte range still digests to the same value, so
both signatures stay valid.

The honest nuance, which is worth volunteering: after a second signature the first no longer
covers the end of the file. DocuTrust surfaces that as
`POST_SIGNATURE_INCREMENTAL_UPDATE` and explicitly marks it *not* cryptographically proven
tampering — because appending is exactly how legitimate counter-signatures and permitted
form-filling work. Both behaviours are asserted in the attack suite.

---

## Time and revocation

### What is timestamping and why does it matter?

**Short answer.** The signer's claimed signing time is just a claim. Only an RFC 3161
timestamp from a third party is evidence.

**Detail.** A signature contains a `signing-time` attribute that the signer chooses. It can
say anything. A Timestamp Authority signs a hash of your signature with its own key,
attesting that it existed at that moment.

This matters because certificates expire. Without a trusted timestamp a verifier cannot
distinguish a signature made while the certificate was valid — legitimate, since expiry does
not retroactively forge anything — from one made after expiry with a key that should have
been retired. DocuTrust has no TSA configured and reports `NOT_AVAILABLE`.

### Why OCSP and CRL?

A certificate can be valid by date yet revoked — key compromise, employee departure,
mis-issuance. A **CRL** is a signed list of revoked serials, simple but potentially large
and stale. **OCSP** queries a responder about one certificate: fresher, but needs the
responder reachable and reveals which certificate you are checking.

DocuTrust distinguishes `GOOD`, `REVOKED`, `UNKNOWN`, `NOT_CHECKED` and `ERROR`. Only
`GOOD` is positive evidence. With checking disabled it reports `NOT_CHECKED` — never
`GOOD`. Reporting "we did not look" as "all clear" is exactly the false assurance the
system exists to avoid.

---

## Key management

### Why use an HSM?

**Short answer.** So the private key cannot be stolen, because it cannot be exported at all.

**Detail.** In this build the key sits in a PKCS#12 file and is loaded into process memory.
Anyone who reads the file and its password can sign as you, indefinitely and undetectably.
An HSM or cloud KMS generates the key inside the device; there is no export API. You send
bytes in and get a signature back. Compromising the server no longer means compromising the
key — an attacker can sign only while they retain access, and every use is logged
independently.

This is why `SigningProvider` never exposes a `PrivateKey`. A design built around retrieving
the key would make HSM and KMS providers impossible to implement without weakening them.

---

## Engineering judgement

### Why shouldn't we implement our own crypto?

**Short answer.** Cryptographic code fails in ways that tests do not catch.

**Detail.** Timing side channels, padding oracles, biased nonces, malleable encodings,
non-constant-time comparison — none of these make a test fail. An implementation that
passes its own tests is not evidence of correctness; it is evidence the author has not yet
found the bug. A correct-looking RSA implementation that leaks key bits through timing is
indistinguishable from a good one until somebody measures it.

Libraries like Bouncy Castle have had years of expert scrutiny and real CVEs found and
fixed. They also come with an advisory feed; hand-written crypto does not.

### What is the difference between certificate validity and document integrity?

**Short answer.** They answer different questions and can disagree — the tampered case is
exactly when they do.

**Detail.** Certificate validity asks: is this certificate parseable, within its validity
window, not revoked, and does it chain to someone we trust? Document integrity asks: are
these bytes the bytes that were signed?

A tampered document typically has integrity `MODIFIED`, signature `INVALID`, and a
certificate that is still perfectly `VALID`. The certificate did not change — the document
did. Reporting "certificate invalid" there is wrong and actively misleading: it sends an
investigator after the signer's credentials when the real problem is that someone edited the
contract.

### What attacks does DocuTrust defend against?

- Modifying content after signing — detected cryptographically, with proof.
- Corrupting or replacing signature bytes.
- Presenting a certificate that does not match the signing key.
- Self-signed or untrusted certificates — surfaced as amber, never green.
- Expired or not-yet-valid certificates — reported distinctly.
- Retroactive edits to the audit log — detected by chain recomputation.
- Malformed or non-PDF uploads.
- Cross-user document access; email enumeration via login timing.

### What attacks does it *not* defend against?

Answering this well matters more than the previous question.

- **Anything that makes the content false rather than changed.** A signature proves a
  document is unchanged since signing. It says nothing about whether it is true.
- **A compromised trusted CA.** If a CA in the trust store mis-issues, DocuTrust reports
  the result as trusted. That is inherent to PKI.
- **Theft of the signing key.** A file-held key can be copied. This is the argument for an
  HSM.
- **Brute-force login and resource exhaustion.** There is no rate limiting. This is the
  most significant missing control.
- **XSS leading to token theft.** The token is in `localStorage`, and there is no
  revocation list, so a stolen token is valid until it expires.
- **An attacker with full database write access.** They can recompute the audit chain and
  leave it consistent. The chain is tamper-evident, not tamper-proof.
- **Proving when something was signed.** Not possible without a trusted timestamp.
- **Reading documents from disk.** No encryption at rest.

### What would you build next, and why?

In order:

1. **Rate limiting** — the largest gap, and it enables two different attacks.
2. **RFC 3161 timestamping** — unlocks PAdES B-T and makes signatures meaningful after
   certificate expiry.
3. **An HSM or KMS provider** — the abstraction already exists; this is what makes
   non-repudiation defensible.
4. **Authorisation tests** — access control is implemented but not proven by tests that
   attempt to break it.
5. **Database-level audit serialisation** — required before running more than one instance.

### What went wrong while building it?

Two real defects, both found by running the system rather than only compiling it:

**X.500 name re-encoding.** The development PKI built issuer names by re-parsing an RFC
2253 string. The names were textually identical to the originals but encoded to different
ASN.1 bytes, and PKIX path building compares *encoded* names — so no trusted path could ever
be constructed and every signature came back untrusted. Fixed by taking the issuer name from
its DER encoding.

**Timestamp precision in the audit chain.** `Instant.now()` carries nanoseconds; a SQL
`TIMESTAMP` column stores microseconds. The value hashed was not the value read back, so
every record failed to recompute and the dashboard reported tampering that had not happened.

The second is the more interesting story, because the failure mode was a *security control
producing a false alarm*. A control that cries wolf is worse than no control, because people
learn to ignore it. The general lesson: anything hashed before storage must be hashed over
exactly the representation storage will return. It is now covered by a test that does a real
database round trip, which the pure unit tests could not have caught.
