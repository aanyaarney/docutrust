package com.docutrust.certificate.domain;

/**
 * Validity state of a single X.509 certificate, considered independently of
 * the document it signed.
 *
 * <p>Critically: a certificate's status is <em>not</em> affected by whether the
 * document content was modified. A tampered PDF signed by a perfectly good
 * certificate still has a {@link #VALID} certificate. Conflating the two is a
 * common and misleading bug, and section 7 of the specification forbids it.
 */
public enum CertificateStatus {

    /** Parsed successfully, currently within its validity window, not revoked. */
    VALID,

    /** Well-formed, but the current time is after {@code notAfter}. */
    EXPIRED,

    /** Well-formed, but the current time is before {@code notBefore}. */
    NOT_YET_VALID,

    /** A revocation responder affirmatively reported this certificate as revoked. */
    REVOKED,

    /**
     * Structurally unusable: could not be parsed, or fails a mandatory
     * constraint such as lacking a key usage permitting digital signatures.
     */
    INVALID,

    /** No certificate was present, or its state could not be established. */
    UNKNOWN
}
