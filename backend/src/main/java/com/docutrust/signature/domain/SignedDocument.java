package com.docutrust.signature.domain;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Objects;

/**
 * A signed PDF together with the facts describing how it was signed.
 *
 * <p>{@code pdfBytes} is a complete, standalone PDF. It can be opened in any
 * conformant reader and its signature verified by any conformant validator —
 * DocuTrust is not required to interpret its own output.
 *
 * @param pdfBytes           the signed PDF
 * @param signerCertificate  certificate whose key produced the signature
 * @param signatureAlgorithm e.g. {@code SHA256withRSA}
 * @param digestAlgorithm    e.g. {@code SHA-256}
 * @param signingTime        time asserted in the signature
 * @param providerName       key custody mechanism used
 * @param signatureFormat    e.g. {@code PAdES-B-B}
 */
public record SignedDocument(
        byte[] pdfBytes,
        X509Certificate signerCertificate,
        String signatureAlgorithm,
        String digestAlgorithm,
        Instant signingTime,
        String providerName,
        String signatureFormat
) {

    public SignedDocument {
        Objects.requireNonNull(pdfBytes, "pdfBytes");
        pdfBytes = pdfBytes.clone();
    }

    @Override
    public byte[] pdfBytes() {
        return pdfBytes.clone();
    }

    public int sizeInBytes() {
        return pdfBytes.length;
    }
}
