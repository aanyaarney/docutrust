package com.docutrust.audit.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import com.docutrust.audit.domain.AuditEventType;

/**
 * A persisted audit record, carrying its position in the hash chain.
 *
 * <p>There are no setters. Audit rows are append-only by design: a record that
 * can be mutated through the ORM is a record whose chain hash can drift out of
 * sync with its contents, which would produce false integrity alarms and
 * undermine the point of chaining them.
 */
@Entity
@Table(name = "audit_events")
public class AuditEventEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "sequence_number", nullable = false, unique = true)
    private long sequenceNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", length = 64, nullable = false)
    private AuditEventType eventType;

    @Column(name = "document_id", length = 36)
    private String documentId;

    @Column(name = "user_id", length = 36)
    private String userId;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "correlation_id", length = 64)
    private String correlationId;

    @Column(name = "details", length = 2048)
    private String details;

    @Column(name = "previous_record_hash", length = 64, nullable = false)
    private String previousRecordHash;

    @Column(name = "record_hash", length = 64, nullable = false)
    private String recordHash;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    protected AuditEventEntity() {
    }

    public AuditEventEntity(String id, long sequenceNumber, AuditEventType eventType,
                            String documentId, String userId, String ipAddress,
                            String correlationId, String details, String previousRecordHash,
                            String recordHash, Instant occurredAt) {
        this.id = id;
        this.sequenceNumber = sequenceNumber;
        this.eventType = eventType;
        this.documentId = documentId;
        this.userId = userId;
        this.ipAddress = ipAddress;
        this.correlationId = correlationId;
        this.details = details;
        this.previousRecordHash = previousRecordHash;
        this.recordHash = recordHash;
        this.occurredAt = occurredAt;
    }

    public String getId() {
        return id;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public AuditEventType getEventType() {
        return eventType;
    }

    public String getDocumentId() {
        return documentId;
    }

    public String getUserId() {
        return userId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public String getDetails() {
        return details;
    }

    public String getPreviousRecordHash() {
        return previousRecordHash;
    }

    public String getRecordHash() {
        return recordHash;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }
}
