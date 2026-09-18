package com.docutrust.verification.domain;

/**
 * Conclusion about whether, and how, a document was modified after signing.
 *
 * <p>The {@code cryptographicallyProven} flag is the important field. It
 * separates findings that are mathematical certainties from findings that are
 * structural interpretation:
 *
 * <ul>
 *   <li><b>Proven</b> — a digest mismatch over the signed byte range. The bytes
 *       are demonstrably not the bytes that were signed. No judgement involved.</li>
 *   <li><b>Best-effort</b> — observations about PDF revision structure, such as
 *       content appended after a signature. Informative, but such an update may
 *       be entirely legitimate (a counter-signature, permitted form filling).</li>
 * </ul>
 *
 * Presenting these as equivalent would overstate what DocuTrust knows.
 * Specification section 19 requires the distinction be explicit.
 *
 * @param tampered                whether a modification was detected
 * @param modificationType        classification of the modification
 * @param explanation             plain-language description for the reader
 * @param affectedRevision        1-based PDF revision implicated, if determinable
 * @param cryptographicallyProven whether this rests on cryptographic proof
 */
public record TamperAnalysisResult(
        boolean tampered,
        ModificationType modificationType,
        String explanation,
        Integer affectedRevision,
        boolean cryptographicallyProven
) {

    /** No modification detected; the signed bytes verify exactly. */
    public static TamperAnalysisResult none() {
        return new TamperAnalysisResult(
                false,
                ModificationType.NONE,
                "No modification detected. The content covered by the signature is "
                        + "byte-for-byte identical to what was signed.",
                null,
                true);
    }

    /**
     * Content covered by the signature changed. This is the proven case: the
     * recomputed digest does not match the signed digest.
     */
    public static TamperAnalysisResult signedContentChanged(Integer revision) {
        return new TamperAnalysisResult(
                true,
                ModificationType.SIGNED_CONTENT_CHANGED,
                "The content protected by this signature was modified after signing. "
                        + "The digest recomputed over the signed byte range does not match the "
                        + "digest recorded in the signature. This is cryptographic proof of "
                        + "modification, though it does not identify which content changed.",
                revision,
                true);
    }

    /** The CMS structure could not be parsed. */
    public static TamperAnalysisResult signatureCorrupted() {
        return new TamperAnalysisResult(
                true,
                ModificationType.SIGNATURE_CORRUPTED,
                "The signature structure itself could not be parsed. The signature bytes "
                        + "are damaged or were overwritten.",
                null,
                true);
    }

    /**
     * The signature verifies, but later revisions were appended.
     *
     * <p>Flagged as {@code tampered = false}: the signed content is intact and
     * nothing here proves wrongdoing. It is reported so a reader knows the
     * visible document may differ from the signed revision.
     */
    public static TamperAnalysisResult postSignatureUpdate(int revisionCount, Integer affectedRevision) {
        return new TamperAnalysisResult(
                false,
                ModificationType.POST_SIGNATURE_INCREMENTAL_UPDATE,
                "The signature is valid and the content it covers is unchanged, but the file "
                        + "contains " + revisionCount + " revisions, with content appended after this "
                        + "signature. Incremental updates are a normal part of PDF - additional "
                        + "signatures and permitted form filling both work this way - so this is an "
                        + "observation, not a finding of tampering.",
                affectedRevision,
                false);
    }

    /** Modification state could not be established. */
    public static TamperAnalysisResult unknown(String reason) {
        return new TamperAnalysisResult(
                false,
                ModificationType.UNKNOWN,
                reason,
                null,
                false);
    }
}
