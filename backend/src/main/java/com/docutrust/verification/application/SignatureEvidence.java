package com.docutrust.verification.application;

/**
 * Raw observations about one signature, gathered before any interpretation.
 *
 * <p>Separating observation from classification keeps
 * {@link TamperAnalysisService} a pure function over facts, which makes it
 * directly testable without constructing PDFs.
 *
 * @param cmsParsed             whether the CMS structure could be parsed at all
 * @param digestMismatch        whether the digest over the signed byte range
 *                              failed to match the digest inside the signed
 *                              attributes — cryptographic proof of modification
 * @param signatureVerified     whether the signature itself verified against the
 *                              signer's public key
 * @param coversEntireDocument  whether the signed byte range reaches the end of
 *                              the file
 * @param revisionCount         number of PDF revisions present in the file
 * @param signatureIndex        0-based index of this signature
 */
public record SignatureEvidence(
        boolean cmsParsed,
        boolean digestMismatch,
        boolean signatureVerified,
        boolean coversEntireDocument,
        int revisionCount,
        int signatureIndex
) {
}
