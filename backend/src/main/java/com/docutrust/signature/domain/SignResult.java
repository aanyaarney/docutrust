package com.docutrust.signature.domain;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;

/**
 * Outcome of a successful signature operation.
 *
 * @param cmsSignedData      DER-encoded detached CMS SignedData structure
 * @param signerCertificate  certificate whose private key produced the signature
 * @param signatureAlgorithm e.g. {@code SHA256withRSA}
 * @param digestAlgorithm    e.g. {@code SHA-256}
 * @param signingTime        time asserted in the signed attributes
 * @param providerName       provider that performed the operation
 */
public record SignResult(
        byte[] cmsSignedData,
        X509Certificate signerCertificate,
        String signatureAlgorithm,
        String digestAlgorithm,
        Instant signingTime,
        String providerName
) {

    public SignResult {
        Objects.requireNonNull(cmsSignedData, "cmsSignedData");
        Objects.requireNonNull(signerCertificate, "signerCertificate");
        cmsSignedData = cmsSignedData.clone();
    }

    @Override
    public byte[] cmsSignedData() {
        return cmsSignedData.clone();
    }
}
