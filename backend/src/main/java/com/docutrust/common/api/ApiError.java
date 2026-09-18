package com.docutrust.common.api;

import java.time.Instant;

/**
 * The single error shape returned by every endpoint.
 *
 * <p>Carries a stable machine-readable {@code code}, a message safe to show a
 * user, and a {@code correlationId} that ties the response to server-side logs.
 * That identifier is what lets support investigate a failure without the
 * response itself having to carry internal detail.
 *
 * <p>Never contains stack traces, SQL, filesystem paths, class names, key
 * material or configuration values. Those belong in logs, which are access
 * controlled; error responses are not (specification section 28).
 *
 * @param code          stable identifier, e.g. {@code DOCUMENT_NOT_FOUND}
 * @param message       explanation safe for display
 * @param correlationId identifier shared with the server log entry
 * @param timestamp     when the error was produced
 */
public record ApiError(String code, String message, String correlationId, Instant timestamp) {

    public static ApiError of(String code, String message, String correlationId) {
        return new ApiError(code, message, correlationId, Instant.now());
    }
}
