# ADR-004: Signing Provider Abstraction

- **Status:** Accepted
- **Date:** 2026-09-15

## Context

The development build signs with a PKCS#12 file. Production signing of consequence should
use an HSM or cloud KMS, where the private key never leaves the device. These have
fundamentally different capabilities: a PKCS#12 file can hand you a `PrivateKey` object;
AWS KMS cannot and never will.

## Decision

Introduce a `SigningProvider` interface that takes content and returns a complete CMS
SignedData structure, plus the signer's certificate chain.

Critically, the interface **never exposes a `PrivateKey`**. The only operation is "sign
these bytes".

CMS assembly is shared in `CmsSignedDataFactory` so that providers differ only in how the
raw signature is produced, not in the structure they emit.

## Alternatives considered

**Expose a `PrivateKey` from a key-loading interface.** Rejected, and this is the decision
that matters. It is the obvious design and it permanently excludes HSM and KMS backends,
because those devices exist precisely so that the key cannot be exported. Any provider
would have to either weaken its security model or fail to implement the interface. Getting
this wrong early would have required reworking every call site later.

**Concrete class, refactor when needed.** Rejected. The seam costs almost nothing now and
would be invasive to introduce once signing logic has spread.

**Full JCA `Provider` implementation.** Rejected as heavier than required; a narrow
domain interface is easier to implement correctly for each backend.

## Consequences

**Positive**
- Business logic has no knowledge of PKCS#12; `DocumentService` depends only on the interface.
- Future HSM and KMS providers are implementable without weakening their key custody.
- Tests construct a provider directly from an in-memory generated PKI, with no keystore file.
- All providers emit structurally identical CMS, since assembly is shared.

**Negative**
- One more indirection between the service layer and the signing operation.
- Providers that need per-call parameters (a KMS key ARN, a PKCS#11 slot) must carry them
  as construction-time configuration, since the interface is deliberately narrow.

**Status note.** Only `Pkcs12SigningProvider` is implemented. SoftHSM, AWS KMS, Azure Key
Vault, Google Cloud KMS and India eSign are documented extension points, deliberately not
stubbed to appear functional.
