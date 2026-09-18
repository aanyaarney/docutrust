package com.docutrust.verification.domain;

/**
 * Whether the content covered by a signature is byte-for-byte what was signed.
 *
 * <p>Determined cryptographically: the digest is recomputed over the signature's
 * byte range and compared with the digest inside the signed attributes. This is
 * proof, not inference.
 */
public enum IntegrityStatus {

    /** Recomputed digest matches the signed digest exactly. */
    INTACT,

    /**
     * The digest does not match. Content protected by the signature changed
     * after it was applied.
     */
    MODIFIED,

    /** Integrity could not be evaluated, e.g. the byte range is unreadable. */
    UNKNOWN
}
