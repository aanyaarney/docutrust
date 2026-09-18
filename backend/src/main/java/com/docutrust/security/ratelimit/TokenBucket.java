package com.docutrust.security.ratelimit;

/**
 * A token bucket.
 *
 * <p>Tokens refill continuously at a fixed rate up to a capacity. Each request
 * consumes one. An empty bucket rejects until enough time has passed to refill.
 *
 * <h2>Why a token bucket rather than a fixed window</h2>
 * A fixed window ("60 requests per minute") allows a burst of 120 requests
 * straddling a window boundary — 60 at 11:59:59 and 60 more at 12:00:00 — which
 * defeats the point of the limit at exactly the moment an attacker is trying
 * hardest. A token bucket has no boundary to straddle: the refill is continuous,
 * so the long-run rate is enforced while still permitting a controlled burst up
 * to {@code capacity}.
 *
 * <p>Refill is computed lazily from elapsed time rather than by a background
 * timer, so idle buckets cost nothing.
 *
 * <p>Instances are mutated under their own monitor. Contention is per key
 * (per address or per account), so lock hold times are negligible.
 */
final class TokenBucket {

    private final long capacity;
    private final double tokensPerNanosecond;

    private double tokens;
    private long lastRefillNanos;

    /**
     * @param capacity       maximum tokens, and therefore the largest burst allowed
     * @param refillPerMinute tokens added per minute, the sustained rate
     */
    TokenBucket(long capacity, long refillPerMinute) {
        this.capacity = capacity;
        this.tokensPerNanosecond = refillPerMinute / 60_000_000_000.0;
        this.tokens = capacity;
        this.lastRefillNanos = System.nanoTime();
    }

    /**
     * Attempts to consume one token.
     *
     * @return {@code true} if the request is allowed
     */
    synchronized boolean tryConsume() {
        refill();
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    /** Seconds until at least one token is available. At least 1 when empty. */
    synchronized long retryAfterSeconds() {
        refill();
        if (tokens >= 1.0) {
            return 0;
        }
        double needed = 1.0 - tokens;
        double seconds = needed / (tokensPerNanosecond * 1_000_000_000.0);
        return Math.max(1L, (long) Math.ceil(seconds));
    }

    /** Whether this bucket is full, and so carries no state worth retaining. */
    synchronized boolean isFull() {
        refill();
        return tokens >= capacity;
    }

    private void refill() {
        long now = System.nanoTime();
        long elapsed = now - lastRefillNanos;
        if (elapsed <= 0) {
            return;
        }
        tokens = Math.min(capacity, tokens + elapsed * tokensPerNanosecond);
        lastRefillNanos = now;
    }
}
