package com.docutrust.certificate.infrastructure;

import java.security.cert.X509Certificate;

import com.docutrust.certificate.domain.RevocationService;
import com.docutrust.certificate.domain.RevocationStatus;

/**
 * Revocation checking turned off.
 *
 * <p>The default for local development, where the development PKI publishes no
 * OCSP responder or CRL distribution point. Always reports
 * {@link RevocationStatus#NOT_CHECKED} — honestly stating that nothing was
 * verified rather than implying a clean result.
 *
 * <p>This is not a stub pretending to be a real implementation. It is a
 * deliberate, correctly-reporting configuration.
 */
public class DisabledRevocationService implements RevocationService {

    @Override
    public RevocationStatus check(X509Certificate certificate, X509Certificate issuer) {
        return RevocationStatus.NOT_CHECKED;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}
