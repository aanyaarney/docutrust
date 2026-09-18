package com.docutrust.timestamp.domain;

import java.time.Instant;

/**
 * Outcome of requesting a timestamp token.
 *
 * @param available     whether a token was actually obtained
 * @param token         DER-encoded RFC 3161 token, or {@code null}
 * @param authorityName the TSA that issued it, or {@code null}
 * @param generatedAt   the time the TSA attested, or {@code null}
 * @param reason        why no token is present, when {@code available} is false
 */
public record TimestampResult(
        boolean available,
        byte[] token,
        String authorityName,
        Instant generatedAt,
        String reason
) {

    public TimestampResult {
        token = token == null ? null : token.clone();
    }

    @Override
    public byte[] token() {
        return token == null ? null : token.clone();
    }

    /**
     * No token was obtained.
     *
     * <p>The only honest result when no authority is configured. Deliberately
     * carries a reason so the absence can be explained rather than merely shown
     * as a blank.
     */
    public static TimestampResult unavailable(String reason) {
        return new TimestampResult(false, null, null, null, reason);
    }

    public static TimestampResult of(byte[] token, String authorityName, Instant generatedAt) {
        return new TimestampResult(true, token, authorityName, generatedAt, null);
    }
}
