package com.docutrust.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.audit.domain.ChainVerificationResult;

/**
 * Verifies the audit chain survives a real database round trip.
 *
 * <p>This exists because of a defect the pure unit tests could not see. Those
 * tests build records in memory and verify them in memory, so the values hashed
 * are byte-identical to the values checked. Persistence breaks that assumption:
 * {@code Instant.now()} carries nanosecond precision, a SQL {@code TIMESTAMP}
 * column stores microseconds, and the truncation on write meant every record
 * failed to recompute on read.
 *
 * <p>The symptom was the worst possible one — an integrity control reporting
 * tampering that had not happened. A control that cries wolf is worse than no
 * control, because people learn to ignore it.
 *
 * <p>The lesson generalises: anything whose hash is computed before storage
 * must be hashed over exactly the representation that storage will return.
 */
@SpringBootTest
@ActiveProfiles("local")
@DisplayName("Audit chain integrity across persistence")
class AuditChainPersistenceTest {

    @Autowired
    private AuditService auditService;

    @Test
    @DisplayName("A chain written to the database still verifies when read back")
    void chainSurvivesPersistence() {
        for (int i = 0; i < 12; i++) {
            auditService.record(AuditEventType.DOCUMENT_UPLOADED,
                    "document-" + i, "user-alpha", "Round-trip check " + i);
        }

        ChainVerificationResult result = auditService.verifyChain();

        assertThat(result.intact())
                .as("chain must verify after a database round trip: %s", result.explanation())
                .isTrue();
        assertThat(result.recordsChecked()).isGreaterThanOrEqualTo(12);
        assertThat(result.firstBrokenSequence()).isNull();
    }

    @Test
    @DisplayName("Recorded events are retrievable by document")
    void eventsAreRetrievableByDocument() {
        auditService.record(AuditEventType.DOCUMENT_SIGNED, "doc-retrieval", "user-beta", "Signed");
        auditService.record(AuditEventType.DOCUMENT_DOWNLOADED, "doc-retrieval", "user-beta", "Downloaded");

        var history = auditService.historyFor("doc-retrieval");

        assertThat(history).hasSize(2);
        assertThat(history.get(0).eventType()).isEqualTo(AuditEventType.DOCUMENT_SIGNED);
        assertThat(history.get(1).eventType()).isEqualTo(AuditEventType.DOCUMENT_DOWNLOADED);

        // Sequence numbers must be strictly increasing for the chain to hold.
        assertThat(history.get(1).sequence()).isGreaterThan(history.get(0).sequence());
    }
}
