package com.docutrust.audit.application;

import java.util.List;
import java.util.Objects;

import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.audit.domain.ChainVerificationResult;

/**
 * Verifies that the audit log has not been altered since it was written.
 *
 * <h2>What the chain does and does not guarantee</h2>
 * Each record's hash covers both its own contents and the hash of its
 * predecessor. Editing any historical record changes its hash, which breaks
 * every link after it. Deleting a record breaks the link across the gap.
 * Inserting one breaks the sequence. So any single-point edit is detectable by
 * recomputation.
 *
 * <p>This is a <strong>hash-chained tamper-evident log</strong>, not a
 * blockchain: there is no distributed consensus and no independent replication.
 * An attacker with unrestricted write access to the database could recompute
 * the entire chain from the point of their edit onward and leave it internally
 * consistent. The chain raises the cost and visibility of tampering; it does
 * not make tampering impossible.
 *
 * <p>Making that limitation explicit matters more than the feature itself.
 * Publishing periodic chain-head digests to independent storage, or
 * timestamping them with a TSA, is what would close the gap — that is a
 * documented future enhancement, not something claimed today.
 */
public class AuditIntegrityService {

    private final AuditChainHasher hasher;

    public AuditIntegrityService(AuditChainHasher hasher) {
        this.hasher = Objects.requireNonNull(hasher, "hasher");
    }

    /**
     * Recomputes the chain over {@code records}, which must be ordered by
     * ascending sequence.
     */
    public ChainVerificationResult verifyChain(List<AuditRecord> records) {
        if (records == null || records.isEmpty()) {
            return ChainVerificationResult.intact(0);
        }

        String expectedPrevious = AuditRecord.GENESIS_HASH;
        long previousSequence = 0;

        for (AuditRecord record : records) {
            // 1. Sequence continuity - catches insertion and deletion.
            if (record.sequence() != previousSequence + 1) {
                return ChainVerificationResult.broken(records.size(), record.sequence(),
                        "Expected sequence " + (previousSequence + 1) + " but found "
                                + record.sequence() + ". A record appears to have been inserted or removed.");
            }

            // 2. Linkage - catches a record being detached from its predecessor.
            if (!expectedPrevious.equals(record.previousRecordHash())) {
                return ChainVerificationResult.broken(records.size(), record.sequence(),
                        "This record's stored previous-hash does not match the actual hash of the "
                                + "preceding record. The chain has been re-linked or a record was replaced.");
            }

            // 3. Content - catches any edit to the record's own fields.
            String recomputed = hasher.computeHash(record, expectedPrevious);
            if (!recomputed.equals(record.recordHash())) {
                return ChainVerificationResult.broken(records.size(), record.sequence(),
                        "The record's contents do not hash to its stored hash. This record was "
                                + "modified after it was written.");
            }

            expectedPrevious = record.recordHash();
            previousSequence = record.sequence();
        }

        return ChainVerificationResult.intact(records.size());
    }

    /**
     * Produces the next record in the chain, with its hashes populated.
     *
     * @param record   the record to append; its hash fields are ignored
     * @param previous the current chain head, or {@code null} if the log is empty
     */
    public AuditRecord link(AuditRecord record, AuditRecord previous) {
        String previousHash = previous == null ? AuditRecord.GENESIS_HASH : previous.recordHash();
        String hash = hasher.computeHash(record, previousHash);
        return record.withHashes(previousHash, hash);
    }
}
