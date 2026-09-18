package com.docutrust.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.docutrust.audit.application.AuditChainHasher;
import com.docutrust.audit.application.AuditIntegrityService;
import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.audit.domain.ChainVerificationResult;
import com.docutrust.common.crypto.Sha256DocumentHashService;

@DisplayName("Hash-chained tamper-evident audit log")
class AuditIntegrityServiceTest {

    private final AuditChainHasher hasher = new AuditChainHasher(new Sha256DocumentHashService());
    private final AuditIntegrityService service = new AuditIntegrityService(hasher);

    /** Builds a linked chain of {@code count} records. */
    private List<AuditRecord> buildChain(int count) {
        List<AuditRecord> chain = new ArrayList<>();
        AuditRecord previous = null;
        Instant base = Instant.parse("2026-09-15T10:00:00Z");

        for (int i = 1; i <= count; i++) {
            AuditRecord unlinked = new AuditRecord(
                    i,
                    UUID.nameUUIDFromBytes(("record-" + i).getBytes()).toString(),
                    AuditEventType.DOCUMENT_UPLOADED,
                    "doc-" + i,
                    "user-alpha",
                    base.plus(i, ChronoUnit.MINUTES),
                    "203.0.113.10",
                    "corr-" + i,
                    "Document uploaded",
                    null, null);

            AuditRecord linked = service.link(unlinked, previous);
            chain.add(linked);
            previous = linked;
        }
        return chain;
    }

    @Test
    @DisplayName("An untouched chain verifies as intact")
    void intactChainVerifies() {
        ChainVerificationResult result = service.verifyChain(buildChain(5));

        assertThat(result.intact()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(5);
        assertThat(result.firstBrokenSequence()).isNull();
    }

    @Test
    @DisplayName("An empty log is intact, not broken")
    void emptyChainIsIntact() {
        assertThat(service.verifyChain(List.of()).intact()).isTrue();
    }

    @Test
    @DisplayName("The first record links to the genesis hash")
    void firstRecordLinksToGenesis() {
        assertThat(buildChain(1).get(0).previousRecordHash())
                .isEqualTo(AuditRecord.GENESIS_HASH);
    }

    @Test
    @DisplayName("Editing a historical record's contents is detected")
    void editedRecordIsDetected() {
        List<AuditRecord> chain = new ArrayList<>(buildChain(5));

        // Rewrite record 3's details, leaving its stored hashes untouched -
        // exactly what someone altering history in the database would do.
        AuditRecord original = chain.get(2);
        chain.set(2, new AuditRecord(
                original.sequence(), original.id(), original.eventType(),
                original.documentId(), original.userId(), original.timestamp(),
                original.ipAddress(), original.correlationId(),
                "Document uploaded (quietly altered)",
                original.previousRecordHash(), original.recordHash()));

        ChainVerificationResult result = service.verifyChain(chain);

        assertThat(result.intact()).isFalse();
        assertThat(result.firstBrokenSequence()).isEqualTo(3L);
        assertThat(result.explanation()).contains("modified after it was written");
    }

    @Test
    @DisplayName("Deleting a record from the middle is detected")
    void deletedRecordIsDetected() {
        List<AuditRecord> chain = new ArrayList<>(buildChain(5));
        chain.remove(2); // drop sequence 3

        ChainVerificationResult result = service.verifyChain(chain);

        assertThat(result.intact()).isFalse();
        assertThat(result.firstBrokenSequence()).isEqualTo(4L);
        assertThat(result.explanation()).contains("inserted or removed");
    }

    @Test
    @DisplayName("Re-linking a record to a different predecessor is detected")
    void relinkedRecordIsDetected() {
        List<AuditRecord> chain = new ArrayList<>(buildChain(4));

        AuditRecord target = chain.get(2);
        chain.set(2, target.withHashes(
                "f".repeat(64),        // a plausible-looking but wrong predecessor
                target.recordHash()));

        ChainVerificationResult result = service.verifyChain(chain);

        assertThat(result.intact()).isFalse();
        assertThat(result.firstBrokenSequence()).isEqualTo(3L);
    }

    @Test
    @DisplayName("Length-prefixed encoding prevents field-boundary collisions")
    void fieldBoundariesCannotBeShifted() {
        Instant when = Instant.parse("2026-09-15T10:00:00Z");

        // These two records differ only in where the boundary between userId
        // and details falls. A naive separator-joined canonical form would hash
        // both to the same value; length prefixing must keep them distinct.
        AuditRecord a = new AuditRecord(1, "id", AuditEventType.DOCUMENT_VIEWED,
                "doc", "alice", when, "203.0.113.1", "corr", "extra", null, null);

        AuditRecord b = new AuditRecord(1, "id", AuditEventType.DOCUMENT_VIEWED,
                "doc", "aliceextra", when, "203.0.113.1", "corr", "", null, null);

        String hashA = hasher.computeHash(a, AuditRecord.GENESIS_HASH);
        String hashB = hasher.computeHash(b, AuditRecord.GENESIS_HASH);

        assertThat(hashA).isNotEqualTo(hashB);
    }

    @Test
    @DisplayName("A null field hashes differently from an empty one")
    void nullIsDistinctFromEmpty() {
        Instant when = Instant.parse("2026-09-15T10:00:00Z");

        AuditRecord withNull = new AuditRecord(1, "id", AuditEventType.DOCUMENT_VIEWED,
                "doc", null, when, "203.0.113.1", "corr", "d", null, null);

        AuditRecord withEmpty = new AuditRecord(1, "id", AuditEventType.DOCUMENT_VIEWED,
                "doc", "", when, "203.0.113.1", "corr", "d", null, null);

        assertThat(hasher.computeHash(withNull, AuditRecord.GENESIS_HASH))
                .isNotEqualTo(hasher.computeHash(withEmpty, AuditRecord.GENESIS_HASH));
    }

    @Test
    @DisplayName("Hashing is deterministic across repeated computation")
    void hashingIsDeterministic() {
        AuditRecord record = buildChain(1).get(0);

        assertThat(hasher.computeHash(record, AuditRecord.GENESIS_HASH))
                .isEqualTo(hasher.computeHash(record, AuditRecord.GENESIS_HASH))
                .hasSize(64);
    }
}
