package com.docutrust.audit.application;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.audit.domain.ChainVerificationResult;
import com.docutrust.audit.infrastructure.AuditEventEntity;
import com.docutrust.audit.infrastructure.AuditEventRepository;
import com.docutrust.common.api.CorrelationIdFilter;

/**
 * Appends events to the hash-chained audit log and verifies its integrity.
 *
 * <h2>Serialising appends</h2>
 * Each record's hash depends on its predecessor, so two concurrent appends
 * reading the same chain head would both claim the same sequence number and
 * produce a fork. Appends are therefore serialised.
 *
 * <p><strong>Known limitation:</strong> the lock is per-JVM. It is correct for
 * a single instance, which is what the modular monolith deploys as today. A
 * multi-instance deployment needs database-level serialisation — a
 * {@code SELECT ... FOR UPDATE} on the chain head, or a dedicated sequence
 * table. This is documented rather than silently assumed, because the failure
 * mode would be a corrupted chain reported as tampering.
 */
@Service
public class AuditService {

    private final AuditEventRepository repository;
    private final AuditIntegrityService integrityService;

    /** Guards chain-head read and append. See the class javadoc. */
    private final Object appendLock = new Object();

    public AuditService(AuditEventRepository repository, AuditIntegrityService integrityService) {
        this.repository = repository;
        this.integrityService = integrityService;
    }

    /**
     * Appends an event.
     *
     * <p>Runs in its own transaction so that recording an event does not fail
     * because the surrounding business transaction later rolls back — an audit
     * trail that disappears when an operation fails is least useful precisely
     * when it matters most.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType eventType, String documentId, String userId, String details) {
        synchronized (appendLock) {
            AuditEventEntity head = repository.findFirstByOrderBySequenceNumberDesc().orElse(null);

            long nextSequence = head == null ? 1 : head.getSequenceNumber() + 1;
            String previousHash = head == null ? AuditRecord.GENESIS_HASH : head.getRecordHash();

            AuditRecord unlinked = new AuditRecord(
                    nextSequence,
                    UUID.randomUUID().toString(),
                    eventType,
                    documentId,
                    userId,
                    // Truncated to milliseconds before hashing.
                    //
                    // The record hash covers the timestamp, so the value hashed
                    // must be exactly the value that survives a round trip
                    // through the database. Instant.now() carries nanosecond
                    // precision, while a SQL TIMESTAMP column keeps at most
                    // microseconds - so an untruncated timestamp is silently
                    // altered on write, and every record then fails to
                    // recompute on read. That failure looks exactly like
                    // tampering, which makes it worse than a plain bug: it
                    // would destroy trust in a control whose only job is to be
                    // trustworthy.
                    //
                    // Millisecond precision loses nothing that matters here:
                    // ordering is established by sequence_number, not by time.
                    Instant.now().truncatedTo(ChronoUnit.MILLIS),
                    null,
                    CorrelationIdFilter.current(),
                    details,
                    null,
                    null);

            AuditRecord linked = integrityService.link(unlinked, toRecord(head));

            repository.save(new AuditEventEntity(
                    linked.id(), linked.sequence(), linked.eventType(), linked.documentId(),
                    linked.userId(), linked.ipAddress(), linked.correlationId(), linked.details(),
                    previousHash, linked.recordHash(), linked.timestamp()));
        }
    }

    /** Re-computes the whole chain. */
    @Transactional(readOnly = true)
    public ChainVerificationResult verifyChain() {
        List<AuditRecord> records = repository.findAllByOrderBySequenceNumberAsc()
                .stream().map(AuditService::toRecord).toList();
        return integrityService.verifyChain(records);
    }

    @Transactional(readOnly = true)
    public List<AuditRecord> historyFor(String documentId) {
        return repository.findByDocumentIdOrderBySequenceNumberAsc(documentId)
                .stream().map(AuditService::toRecord).toList();
    }

    @Transactional(readOnly = true)
    public List<AuditRecord> recentActivity() {
        return repository.findTop20ByOrderBySequenceNumberDesc()
                .stream().map(AuditService::toRecord).toList();
    }

    private static AuditRecord toRecord(AuditEventEntity entity) {
        if (entity == null) {
            return null;
        }
        return new AuditRecord(
                entity.getSequenceNumber(), entity.getId(), entity.getEventType(),
                entity.getDocumentId(), entity.getUserId(), entity.getOccurredAt(),
                entity.getIpAddress(), entity.getCorrelationId(), entity.getDetails(),
                entity.getPreviousRecordHash(), entity.getRecordHash());
    }
}
