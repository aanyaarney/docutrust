package com.docutrust.verification.domain;

import java.time.Instant;
import java.util.List;

/**
 * The complete result of verifying a submitted document.
 *
 * @param verificationId  stable identifier, safe to share and to embed in a QR code
 * @param verdict         the single overall answer
 * @param headline        short plain-language statement of the verdict
 * @param explanation     what the verdict means and why it was reached
 * @param signatures      per-signature outcomes, in document order
 * @param documentSha256  digest of the submitted file as a whole
 * @param fileName        submitted file name, sanitised
 * @param pageCount       page count, or {@code null} if unreadable
 * @param fileSizeBytes   size of the submitted file
 * @param verifiedAt      when verification ran
 */
public record VerificationReport(
        String verificationId,
        VerificationVerdict verdict,
        String headline,
        String explanation,
        List<SignatureVerificationDetail> signatures,
        String documentSha256,
        String fileName,
        Integer pageCount,
        long fileSizeBytes,
        Instant verifiedAt
) {

    public VerificationReport {
        signatures = signatures == null ? List.of() : List.copyOf(signatures);
    }

    public int signatureCount() {
        return signatures.size();
    }

    /** Whether any signature showed cryptographically proven modification. */
    public boolean hasProvenTampering() {
        return signatures.stream()
                .anyMatch(s -> s.tamperAnalysis().tampered()
                        && s.tamperAnalysis().cryptographicallyProven());
    }
}
