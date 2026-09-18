package com.docutrust.verification.domain;

import java.time.Instant;
import java.util.Arrays;

import com.docutrust.certificate.domain.CertificateValidationResult;

/**
 * Verification outcome for one signature within a document.
 *
 * <p>A document may carry several signatures — an employee, a manager, then HR.
 * Each is verified independently and gets one of these.
 *
 * <p>The fields are deliberately not collapsed into a single status. A tampered
 * document typically has {@code integrity = MODIFIED} and
 * {@code signature = INVALID} while its {@code certificate} remains perfectly
 * {@code VALID} — reporting the certificate as invalid in that situation would
 * be false and actively misleading (specification section 7).
 *
 * @param index                 0-based position within the document
 * @param signerName            name from the PDF signature dictionary, if present
 * @param reason                stated reason for signing, covered by the signature
 * @param location              stated location, covered by the signature
 * @param claimedSigningTime    time the signer asserted; unverified unless timestamped
 * @param integrity             whether the signed bytes are unchanged
 * @param signature             whether the signature verifies cryptographically
 * @param certificate           signer certificate validation outcome
 * @param timestamp             trusted timestamp state
 * @param timestampAuthority    TSA named in the token, or {@code null} if none
 * @param timestampAttestedTime time the TSA attested, or {@code null} if none.
 *                              Distinct from {@code claimedSigningTime}: this is
 *                              asserted by an independent party, that one by the
 *                              signer.
 * @param tamperAnalysis        modification classification
 * @param signatureFormat       e.g. {@code PAdES (ETSI.CAdES.detached)}
 * @param digestAlgorithm       e.g. {@code SHA-256}
 * @param signatureAlgorithm    e.g. {@code SHA256withRSA}
 * @param byteRange             the PDF {@code /ByteRange} array
 * @param coversEntireDocument  whether the signed range reaches the end of the file
 * @param verdict               per-signature verdict
 */
public record SignatureVerificationDetail(
        int index,
        String signerName,
        String reason,
        String location,
        Instant claimedSigningTime,
        IntegrityStatus integrity,
        SignatureStatus signature,
        CertificateValidationResult certificate,
        TimestampStatus timestamp,
        String timestampAuthority,
        Instant timestampAttestedTime,
        TamperAnalysisResult tamperAnalysis,
        String signatureFormat,
        String digestAlgorithm,
        String signatureAlgorithm,
        int[] byteRange,
        boolean coversEntireDocument,
        VerificationVerdict verdict
) {

    public SignatureVerificationDetail {
        byteRange = byteRange == null ? new int[0] : byteRange.clone();
    }

    @Override
    public int[] byteRange() {
        return byteRange.clone();
    }

    /** The {@code /ByteRange} rendered as it appears in the PDF, for the technical view. */
    public String byteRangeDisplay() {
        return byteRange.length == 0 ? "UNAVAILABLE" : Arrays.toString(byteRange);
    }
}
