package com.docutrust.certificate.domain;

/**
 * Outcome of a certificate revocation check (OCSP or CRL).
 *
 * <p>The distinction between {@link #GOOD}, {@link #UNKNOWN} and
 * {@link #NOT_CHECKED} is deliberate and load-bearing. Collapsing them would
 * let DocuTrust imply a revocation check happened when it did not — the exact
 * class of false assurance the platform exists to avoid.
 */
public enum RevocationStatus {

    /** A responder was queried and affirmatively reported the certificate as not revoked. */
    GOOD,

    /** A responder was queried and reported the certificate as revoked. */
    REVOKED,

    /**
     * A check was attempted, but the responder could not answer authoritatively
     * (for example an OCSP "unknown" response). Never render this as valid.
     */
    UNKNOWN,

    /**
     * No check was attempted, because revocation checking is disabled or the
     * certificate declares no OCSP/CRL distribution point.
     *
     * <p>This is the honest default. It is not a failure, and it is not a pass.
     */
    NOT_CHECKED,

    /** A check was attempted but failed technically (network, parse, or timeout). */
    ERROR;

    /**
     * Whether this status represents positive evidence that the certificate is
     * not revoked. Only {@link #GOOD} qualifies.
     */
    public boolean isAffirmativelyGood() {
        return this == GOOD;
    }

    /** Whether this status must block an overall {@code VALID} verdict. */
    public boolean isRevoked() {
        return this == REVOKED;
    }
}
