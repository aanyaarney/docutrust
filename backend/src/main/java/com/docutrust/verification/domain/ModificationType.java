package com.docutrust.verification.domain;

/**
 * Classification of a detected modification.
 *
 * <p>These values are deliberately conservative. DocuTrust reports what it can
 * <em>prove</em> from the signature's byte range and the PDF's revision
 * structure. It does not claim to identify which words changed — that would
 * require comparing against an original it does not have, and asserting it
 * would be a fabricated finding (specification section 18).
 */
public enum ModificationType {

    /** No modification detected. */
    NONE,

    /**
     * Content covered by the signature changed. Proven cryptographically by a
     * digest mismatch over the signed byte range.
     *
     * <p>This is the strongest finding DocuTrust makes: it is mathematical
     * proof that the bytes are not the bytes that were signed.
     */
    SIGNED_CONTENT_CHANGED,

    /**
     * The signature still verifies, but the file carries additional revisions
     * appended after it.
     *
     * <p>Not inherently malicious — this is exactly how legitimate second
     * signatures and permitted form-filling work. It is surfaced because the
     * visible document may differ from the signed revision, and a reader
     * deserves to know that. Best-effort structural observation, not proof of
     * wrongdoing.
     */
    POST_SIGNATURE_INCREMENTAL_UPDATE,

    /** The CMS signature structure could not be parsed; its bytes are damaged. */
    SIGNATURE_CORRUPTED,

    /** A change was detected whose nature DocuTrust cannot classify. */
    UNSUPPORTED_CHANGE,

    /** Modification state could not be established. */
    UNKNOWN
}
