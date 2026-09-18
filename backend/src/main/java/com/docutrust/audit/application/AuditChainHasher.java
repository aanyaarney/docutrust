package com.docutrust.audit.application;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.common.crypto.DocumentHashService;

/**
 * Computes the chain hash for an audit record.
 *
 * <pre>
 *   recordHash = SHA-256( previousRecordHash ‖ canonicalEventData )
 * </pre>
 *
 * <h2>Why the canonical form is length-prefixed</h2>
 * Fields are serialised as {@code length:value} rather than joined with a
 * separator. Naive joining is ambiguous: with a {@code |} separator, the field
 * pair {@code ("a|b", "c")} and {@code ("a", "b|c")} both serialise to
 * {@code a|b|c} and therefore produce an identical hash. An attacker who
 * controls part of a field could exploit that to rewrite a record while keeping
 * its hash intact.
 *
 * <p>Prefixing each value with its length removes the ambiguity: every distinct
 * field tuple has exactly one encoding. This is the same reasoning behind
 * length-prefixed framing in binary protocols.
 */
public class AuditChainHasher {

    private final DocumentHashService hashService;

    public AuditChainHasher(DocumentHashService hashService) {
        this.hashService = hashService;
    }

    /**
     * Computes the hash for {@code record}, chained onto {@code previousHash}.
     *
     * <p>The record's own {@code recordHash} is excluded from the input, since
     * it is the value being produced.
     */
    public String computeHash(AuditRecord record, String previousHash) {
        StringBuilder canonical = new StringBuilder();

        append(canonical, previousHash);
        append(canonical, Long.toString(record.sequence()));
        append(canonical, record.id());
        append(canonical, record.eventType() == null ? null : record.eventType().name());
        append(canonical, record.documentId());
        append(canonical, record.userId());
        append(canonical, instantToString(record.timestamp()));
        append(canonical, record.ipAddress());
        append(canonical, record.correlationId());
        append(canonical, record.details());

        return hashService.calculateSha256(
                canonical.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Appends one field as {@code <byteLength>:<value>;}.
     *
     * <p>A null field is encoded distinctly from an empty one, so that
     * "absent" and "present but blank" cannot collide.
     */
    private void append(StringBuilder builder, String value) {
        if (value == null) {
            builder.append("-1:;");
            return;
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        builder.append(bytes.length).append(':').append(value).append(';');
    }

    /**
     * Serialises the timestamp deterministically.
     *
     * <p>Epoch nanoseconds rather than a formatted string: text formats vary
     * with locale, offset and precision, and a hash must not depend on any of
     * those.
     */
    private String instantToString(Instant instant) {
        if (instant == null) {
            return null;
        }
        return instant.getEpochSecond() + "." + instant.getNano();
    }
}
