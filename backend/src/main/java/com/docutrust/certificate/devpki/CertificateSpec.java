package com.docutrust.certificate.devpki;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * Parameters describing a certificate to be issued by {@link DevPkiGenerator}.
 *
 * <p>A dedicated parameter object rather than a long argument list: certificate
 * issuance has six interdependent inputs, several of which are nullable in
 * meaningful ways ({@code issuerCertificate == null} means self-signed).
 * Positional arguments would make call sites unreadable and easy to transpose.
 *
 * @param subject              subject distinguished name
 * @param issuerCertificate    issuing certificate, or {@code null} for self-signed
 * @param issuerKey            private key that signs this certificate
 * @param publicKey            key pair whose public half is certified
 * @param notBefore            start of the validity window
 * @param notAfter             end of the validity window
 * @param certificateAuthority whether to assert the CA basic constraint
 */
public record CertificateSpec(
        String subject,
        X509Certificate issuerCertificate,
        PrivateKey issuerKey,
        KeyPair publicKey,
        Instant notBefore,
        Instant notAfter,
        boolean certificateAuthority
) {

    public static Builder builder() {
        return new Builder();
    }

    /** Mutable builder; the resulting {@link CertificateSpec} is immutable. */
    public static final class Builder {
        private String subject;
        private X509Certificate issuerCertificate;
        private PrivateKey issuerKey;
        private KeyPair publicKey;
        private Instant notBefore;
        private Instant notAfter;
        private boolean certificateAuthority;

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder issuerCertificate(X509Certificate issuerCertificate) {
            this.issuerCertificate = issuerCertificate;
            return this;
        }

        public Builder issuerKey(PrivateKey issuerKey) {
            this.issuerKey = issuerKey;
            return this;
        }

        public Builder publicKey(KeyPair publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder notBefore(Instant notBefore) {
            this.notBefore = notBefore;
            return this;
        }

        public Builder notAfter(Instant notAfter) {
            this.notAfter = notAfter;
            return this;
        }

        public Builder certificateAuthority(boolean certificateAuthority) {
            this.certificateAuthority = certificateAuthority;
            return this;
        }

        public CertificateSpec build() {
            return new CertificateSpec(subject, issuerCertificate, issuerKey,
                    publicKey, notBefore, notAfter, certificateAuthority);
        }
    }
}
