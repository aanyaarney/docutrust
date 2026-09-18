package com.docutrust.audit.infrastructure;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, String> {

    /** All records in chain order. Required for integrity verification. */
    List<AuditEventEntity> findAllByOrderBySequenceNumberAsc();

    List<AuditEventEntity> findByDocumentIdOrderBySequenceNumberAsc(String documentId);

    /** The current chain head, needed to link the next append. */
    Optional<AuditEventEntity> findFirstByOrderBySequenceNumberDesc();

    List<AuditEventEntity> findTop20ByOrderBySequenceNumberDesc();
}
