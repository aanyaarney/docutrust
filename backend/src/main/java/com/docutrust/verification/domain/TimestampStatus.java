package com.docutrust.verification.domain;

/**
 * State of a trusted timestamp on a signature.
 *
 * <p>There is deliberately no value meaning "the signer said they signed at
 * time X, so that is the time". The {@code signing-time} signed attribute is an
 * unverified claim by the signer, who can set it to anything. Only an RFC 3161
 * token from a Timestamp Authority is evidence of time.
 *
 * <p>When no TSA is configured the answer is {@link #NOT_AVAILABLE}, never
 * {@link #VALID} (specification section 16).
 */
public enum TimestampStatus {

    /** An RFC 3161 token is present and verifies against a trusted TSA certificate. */
    VALID,

    /** A token is present but fails verification, or does not match the signature. */
    INVALID,

    /**
     * No timestamp token is present. Either no TSA was configured at signing
     * time, or the signature format does not carry one.
     */
    NOT_AVAILABLE,

    /** A token is present but was not evaluated. */
    NOT_CHECKED
}
