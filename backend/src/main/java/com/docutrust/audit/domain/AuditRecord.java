package com.docutrust.audit.domain;

import java.time.Instant;

/**
 * One entry in the hash-chained audit log.
 *
 * <h2>What must never appear here</h2>
 * {@code details} is free text and is written to durable storage that operators
 * and, in places, users can read. It must never contain private keys, keystore
 * or account passwords, JWTs or other bearer tokens, {@code Authorization}
 * header values, or document contents. Record identifiers and outcomes, not
 * secrets (specification sections 21 and 30).
 *
 * @param sequence           monotonically increasing position in the chain, from 1
 * @param id                 unique record identifier
 * @param eventType          what happened
 * @param documentId         document concerned, if any
 * @param userId             actor responsible, if known
 * @param timestamp          when the event was recorded
 * @param ipAddress          originating address, where available
 * @param correlationId      request correlation identifier, tying this to logs
 * @param details            short non-sensitive description
 * @param previousRecordHash {@code recordHash} of the preceding record; empty for the first
 * @param recordHash         SHA-256 over the previous hash and this record's canonical form
 */
public record AuditRecord(
        long sequence,
        String id,
        AuditEventType eventType,
        String documentId,
        String userId,
        Instant timestamp,
        String ipAddress,
        String correlationId,
        String details,
        String previousRecordHash,
        String recordHash
) {

    /** Hash value used as the predecessor of the very first record. */
    public static final String GENESIS_HASH = "0".repeat(64);

    /** A copy of this record carrying the supplied chain hashes. */
    public AuditRecord withHashes(String previousHash, String hash) {
        return new AuditRecord(sequence, id, eventType, documentId, userId, timestamp,
                ipAddress, correlationId, details, previousHash, hash);
    }
}
