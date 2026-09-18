package com.docutrust.certificate.domain;

/**
 * Result of building and evaluating a certificate chain from the signer
 * certificate toward a configured trust anchor.
 *
 * <p>DocuTrust's trust model is explicit: certificates embedded in a submitted
 * PDF are treated as <em>claims</em>, never as trust anchors. A chain is
 * {@link #TRUSTED} only when it terminates at an anchor the operator configured
 * in the application trust store.
 */
public enum ChainStatus {

    /**
     * The chain was built and validated all the way to a certificate present
     * in the configured trust store.
     */
    TRUSTED,

    /**
     * The chain is cryptographically coherent — each certificate is properly
     * signed by the next — but its root is not in the configured trust store.
     *
     * <p>This is the amber state. The signature may be mathematically perfect;
     * the signer's identity is simply not vouched for by anyone we trust. A
     * self-signed signer certificate lands here.
     */
    UNTRUSTED,

    /** Issuer certificates needed to complete the chain were not available. */
    INCOMPLETE,

    /**
     * The chain is broken: a certificate's signature does not verify against
     * its claimed issuer, or a path constraint (basic constraints, path length)
     * is violated.
     */
    INVALID,

    /** Chain evaluation was not performed. */
    NOT_CHECKED
}
