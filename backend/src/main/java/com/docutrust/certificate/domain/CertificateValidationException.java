package com.docutrust.certificate.domain;

/**
 * Raised when certificate validation cannot be carried out.
 *
 * <p>Distinct from a validation <em>result</em> that reports a certificate as
 * expired, untrusted or revoked — those are normal outcomes described by
 * {@link CertificateValidationResult}, not errors.
 */
public class CertificateValidationException extends RuntimeException {

    public CertificateValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateValidationException(String message) {
        super(message);
    }
}
