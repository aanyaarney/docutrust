package com.docutrust.signature.domain;

import java.time.Instant;

/**
 * User-supplied options for a signing operation.
 *
 * <p>All fields are optional. {@code reason} and {@code location} are recorded
 * in the PDF signature dictionary and are covered by the signature, so they
 * cannot be altered afterwards without invalidating it.
 *
 * @param reason            stated reason for signing, e.g. "I approve this document"
 * @param location          stated location, e.g. "Bengaluru, IN"
 * @param signerDisplayName human-readable name shown in PDF readers
 * @param signingTime       claimed signing time; defaults to now when {@code null}
 * @param visibleSignature  whether to draw a visible appearance block
 */
public record SignatureParameters(
        String reason,
        String location,
        String signerDisplayName,
        Instant signingTime,
        boolean visibleSignature
) {

    /** Minimal parameters: invisible signature, signing time of now. */
    public static SignatureParameters defaults() {
        return new SignatureParameters(null, null, null, null, false);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String reason;
        private String location;
        private String signerDisplayName;
        private Instant signingTime;
        private boolean visibleSignature;

        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder location(String location) {
            this.location = location;
            return this;
        }

        public Builder signerDisplayName(String signerDisplayName) {
            this.signerDisplayName = signerDisplayName;
            return this;
        }

        public Builder signingTime(Instant signingTime) {
            this.signingTime = signingTime;
            return this;
        }

        public Builder visibleSignature(boolean visibleSignature) {
            this.visibleSignature = visibleSignature;
            return this;
        }

        public SignatureParameters build() {
            return new SignatureParameters(reason, location, signerDisplayName, signingTime, visibleSignature);
        }
    }
}
