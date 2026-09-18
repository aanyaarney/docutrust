package com.docutrust.certificate.domain;

import java.util.List;

/**
 * Outcome of validating a signer certificate and its chain.
 *
 * <p>Every dimension is reported separately rather than reduced to a single
 * boolean. A certificate can be within its validity window yet chain to nobody
 * we trust; it can chain perfectly yet be expired. Callers — and users — need
 * to see which.
 *
 * <p>Note what is <em>absent</em>: nothing here reflects whether the document
 * was modified. Certificate validity and document integrity are independent
 * concerns, and section 7 of the specification explicitly forbids reporting a
 * certificate as invalid merely because document content changed.
 *
 * @param status           overall state of the signer certificate
 * @param details          extracted facts about the signer certificate
 * @param validPeriod      whether the current time falls within the validity window
 * @param chainStatus      result of building a path to a configured trust anchor
 * @param revocationStatus result of the revocation check, including whether one occurred
 * @param chain            certificates forming the built path, leaf-first
 * @param failureReason    human-readable explanation when validation did not succeed
 */
public record CertificateValidationResult(
        CertificateStatus status,
        CertificateDetails details,
        boolean validPeriod,
        ChainStatus chainStatus,
        RevocationStatus revocationStatus,
        List<CertificateDetails> chain,
        String failureReason
) {

    public CertificateValidationResult {
        chain = chain == null ? List.of() : List.copyOf(chain);
    }

    /** Whether the chain reached a configured trust anchor. */
    public boolean isTrusted() {
        return chainStatus == ChainStatus.TRUSTED;
    }

    /**
     * Whether the certificate is usable for signature validation: parseable,
     * within its validity window, and not affirmatively revoked.
     *
     * <p>Trust is <em>not</em> part of this judgement — an untrusted certificate
     * is still a usable certificate; it simply proves no identity.
     */
    public boolean isUsable() {
        return status == CertificateStatus.VALID && !revocationStatus.isRevoked();
    }

    /** Result used when no certificate could be recovered from a signature. */
    public static CertificateValidationResult unavailable(String reason) {
        return new CertificateValidationResult(
                CertificateStatus.UNKNOWN,
                null,
                false,
                ChainStatus.NOT_CHECKED,
                RevocationStatus.NOT_CHECKED,
                List.of(),
                reason);
    }
}
