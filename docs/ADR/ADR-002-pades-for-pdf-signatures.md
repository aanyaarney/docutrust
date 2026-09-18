# ADR-002: PAdES for PDF Digital Signatures

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

DocuTrust must attach signatures to PDFs such that the signature is carried by the
document itself and is verifiable by software other than DocuTrust. If verification only
worked inside this application, the signature would be a private convention rather than
evidence.

Available approaches:

1. A detached signature file distributed alongside the PDF.
2. A hash stored in the database, with the application asserting validity.
3. A signature embedded in the PDF using the standard PDF signature dictionary.

## Decision

Embed the signature in the PDF using **PAdES Baseline-B** (ETSI EN 319 142), with the
`ETSI.CAdES.detached` sub-filter, implemented with Apache PDFBox for PDF mechanics and
Bouncy Castle for CMS construction.

The signature is written as an incremental update: a signature dictionary with a reserved
`/Contents` region and a `/ByteRange` covering the rest of the file.

EU DSS was considered and not adopted. It is the most complete PAdES implementation
available, but it brings a large transitive dependency graph and a heavier abstraction
layer. For Baseline-B, PDFBox plus Bouncy Castle gives direct control over the bytes being
signed, which made the byte-range behaviour easier to reason about and to test. DSS
remains the sensible choice if B-LT or B-LTA levels are pursued.

## Alternatives considered

**Detached signature file.** Rejected. Two files travel separately, so the signature is
routinely lost by email clients and document management systems. No PDF reader would
display signature status.

**Hash in the database.** Rejected, and it is worth naming why: this is not a digital
signature at all. It proves only that the application once recorded a digest. It cannot be
verified by anyone else, provides no signer identity, and collapses entirely if the
database is compromised. The specification explicitly forbids it, and rightly.

**Legacy `adbe.pkcs7.detached`.** Rejected. Widely supported but superseded; PAdES is the
European standard and is what modern validators expect.

## Consequences

**Positive**
- The signed PDF is self-contained and verifiable by Adobe Acrobat, EU DSS, and any other
  conformant validator. DocuTrust is not required to interpret its own output.
- Incremental updates preserve earlier signatures, so multiple signatures work correctly.
- The `/ByteRange` gives an exact, inspectable definition of what is protected.

**Negative**
- Space for the CMS structure must be reserved before its size is known; the reservation
  (16 KB) is a fixed constant that would need raising for very long certificate chains or
  embedded revocation data.
- Baseline-B carries no timestamp, so the time of signing is unproven. Reaching B-T
  requires a TSA integration that is not built.
- PDFBox's signing API needs the whole document in memory, which constrains maximum
  document size.
