package com.docutrust.verification.domain;

/**
 * Result of verifying the CMS signature with the signer's public key.
 *
 * <p>Distinct from {@link IntegrityStatus}: integrity asks "did the bytes
 * change", this asks "does the signature mathematically check out". In the
 * common tampering case both fail together, but they fail for different reasons
 * and a useful report says so.
 */
public enum SignatureStatus {

    /** The signature verifies against the signer certificate's public key. */
    VALID,

    /**
     * The signature is well-formed but does not verify — typically because the
     * signed content changed, or because it was made by a different key.
     */
    INVALID,

    /**
     * The CMS structure itself could not be parsed. The signature bytes are
     * damaged or were deliberately overwritten.
     */
    CORRUPTED,

    /** Verification was not performed or could not be completed. */
    UNKNOWN
}
