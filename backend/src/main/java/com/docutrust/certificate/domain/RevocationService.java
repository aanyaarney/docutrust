package com.docutrust.certificate.domain;

import java.security.cert.X509Certificate;

/**
 * Checks whether a certificate has been revoked, via OCSP or a CRL.
 *
 * <h2>The contract that matters</h2>
 * An implementation that does not perform a check must return
 * {@link RevocationStatus#NOT_CHECKED}. It must never return
 * {@link RevocationStatus#GOOD}. {@code GOOD} asserts that a responder was
 * consulted and affirmatively said the certificate is not revoked; claiming it
 * without having asked is exactly the kind of false assurance the platform is
 * built to avoid (specification section 17).
 *
 * <p>The same applies to failure: an unreachable responder yields
 * {@link RevocationStatus#ERROR}, and an inconclusive answer yields
 * {@link RevocationStatus#UNKNOWN}. Neither is silently upgraded.
 */
public interface RevocationService {

    /**
     * Determines the revocation status of {@code certificate}.
     *
     * @param certificate the certificate to check
     * @param issuer      its issuer, required to build an OCSP request
     * @return the status, including whether a check actually took place
     */
    RevocationStatus check(X509Certificate certificate, X509Certificate issuer);

    /** Whether this implementation performs real checks. */
    boolean isEnabled();
}
