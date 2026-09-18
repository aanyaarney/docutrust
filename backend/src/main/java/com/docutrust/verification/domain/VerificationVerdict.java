package com.docutrust.verification.domain;

/**
 * The single overall answer DocuTrust gives about a submitted document.
 *
 * <p>Three of these map to the three visual states the interface must make
 * unmistakable (specification section 69): green, amber, red.
 *
 * <p>The amber state is the reason this enum is not a boolean. A signature can
 * be mathematically perfect while the signer's identity is vouched for by
 * nobody we trust. Reporting that as "valid" overstates it; reporting it as
 * "invalid" is simply wrong, because the cryptography verified. It gets its own
 * verdict.
 */
public enum VerificationVerdict {

    /**
     * GREEN. The signature verifies, the signed content is unchanged, and the
     * certificate chain reaches a configured trust anchor.
     */
    VALID,

    /**
     * AMBER. The signature verifies and the content is unchanged, but the
     * certificate chain does not reach a configured trust anchor — typically a
     * self-signed signer. Real cryptography, unproven identity.
     */
    VALID_UNTRUSTED,

    /**
     * RED. Content protected by the signature changed after signing. The
     * document is not what was signed.
     */
    TAMPERED,

    /**
     * RED. The signature itself fails cryptographic verification for a reason
     * other than content modification — corrupted signature bytes, a signature
     * made by a key that does not match the certificate, or an unusable
     * certificate.
     */
    INVALID,

    /** The document carries no digital signature at all. Not a failure — a fact. */
    UNSIGNED,

    /**
     * Verification could not be completed: the file is not a readable PDF, or
     * an unexpected error occurred. Explicitly not a pass and not a fail.
     */
    ERROR;

    /** Whether this verdict should be rendered in the green state. */
    public boolean isFullyValid() {
        return this == VALID;
    }

    /** Whether this verdict indicates a genuine security problem (red). */
    public boolean isFailure() {
        return this == TAMPERED || this == INVALID;
    }
}
