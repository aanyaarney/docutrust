package com.docutrust.signature.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * Content to be signed, together with the parameters governing the signature.
 *
 * <p>{@code contentToSign} is the PDF's <strong>signed byte range</strong> —
 * the whole file except the reserved hole that will hold the signature itself.
 * This is the precise input that makes tamper detection cryptographic: altering
 * any byte within this range changes the digest and breaks verification.
 *
 * @param contentToSign     exact bytes covered by the signature
 * @param digestAlgorithm   digest algorithm name, e.g. {@code SHA-256}
 * @param signingTime       claimed signing time, embedded as a signed attribute
 * @param reason            optional stated reason for signing
 * @param location          optional stated location of signing
 * @param signerDisplayName optional human-readable signer name for display
 */
public record SignRequest(
        byte[] contentToSign,
        String digestAlgorithm,
        Instant signingTime,
        String reason,
        String location,
        String signerDisplayName
) {

    public SignRequest {
        Objects.requireNonNull(contentToSign, "contentToSign");
        Objects.requireNonNull(digestAlgorithm, "digestAlgorithm");
        Objects.requireNonNull(signingTime, "signingTime");

        if (contentToSign.length == 0) {
            throw new IllegalArgumentException("Cannot sign empty content");
        }
        // Defensive copy: the signed bytes must not change after construction,
        // or the resulting signature would not describe what the caller checked.
        contentToSign = contentToSign.clone();
    }

    @Override
    public byte[] contentToSign() {
        return contentToSign.clone();
    }

    /**
     * The claimed signing time.
     *
     * <p>This is asserted by the signer, not proven. Only an RFC 3161 timestamp
     * from a trusted authority constitutes evidence of <em>when</em> a signature
     * was made. Verification output must never present this value as a trusted
     * timestamp.
     */
    @Override
    public Instant signingTime() {
        return signingTime;
    }
}
