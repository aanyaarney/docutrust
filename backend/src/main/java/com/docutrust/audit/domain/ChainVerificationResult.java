package com.docutrust.audit.domain;

/**
 * Outcome of re-computing the audit hash chain.
 *
 * @param intact              whether every record's hash and linkage recomputed correctly
 * @param recordsChecked      how many records were examined
 * @param firstBrokenSequence sequence number of the first record that failed, or {@code null}
 * @param explanation         what was found
 */
public record ChainVerificationResult(
        boolean intact,
        long recordsChecked,
        Long firstBrokenSequence,
        String explanation
) {

    public static ChainVerificationResult intact(long recordsChecked) {
        return new ChainVerificationResult(true, recordsChecked, null,
                recordsChecked == 0
                        ? "The audit log is empty. There is nothing to verify."
                        : "All " + recordsChecked + " audit records recomputed correctly. "
                          + "No record has been altered, inserted or removed since it was written.");
    }

    public static ChainVerificationResult broken(long recordsChecked, long sequence, String reason) {
        return new ChainVerificationResult(false, recordsChecked, sequence,
                "Audit chain integrity check FAILED at record " + sequence + ". " + reason);
    }
}
