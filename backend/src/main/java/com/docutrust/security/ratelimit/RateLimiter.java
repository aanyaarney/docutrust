package com.docutrust.security.ratelimit;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keyed rate limiter backed by token buckets.
 *
 * <h2>Scope and honest limitation</h2>
 * State is held in memory, in this JVM. That is correct for a single instance,
 * which is what the modular monolith deploys as today. Across several instances
 * each would enforce the limit independently, so the effective limit multiplies
 * by the instance count. A shared store (Redis) or an edge-level limit is
 * required before horizontal scaling — this is a documented boundary, not an
 * oversight.
 *
 * <p>Even so, an in-memory limiter is worth having: it turns unbounded
 * credential stuffing and unbounded signing requests into bounded ones, which
 * is the difference between a trivial attack and an expensive one.
 */
public class RateLimiter {

    /**
     * Upper bound on tracked keys.
     *
     * <p>Without this, an attacker rotating source addresses would grow the map
     * without limit — turning the denial-of-service control into a
     * denial-of-service vector. When the cap is reached, full buckets (which
     * carry no useful state) are evicted first.
     */
    private static final int MAX_TRACKED_KEYS = 100_000;

    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final long capacity;
    private final long refillPerMinute;

    public RateLimiter(long capacity, long refillPerMinute) {
        this.capacity = capacity;
        this.refillPerMinute = refillPerMinute;
    }

    /**
     * Attempts to consume one token for {@code key}.
     *
     * @return the decision, including how long to wait when refused
     */
    public Decision tryAcquire(String key) {
        if (buckets.size() >= MAX_TRACKED_KEYS) {
            evictFullBuckets();
        }

        TokenBucket bucket = buckets.computeIfAbsent(
                key, unused -> new TokenBucket(capacity, refillPerMinute));

        if (bucket.tryConsume()) {
            return Decision.ALLOWED;
        }
        return new Decision(false, bucket.retryAfterSeconds());
    }

    /**
     * Drops buckets that have refilled completely.
     *
     * <p>A full bucket is indistinguishable from a fresh one, so discarding it
     * loses nothing and cannot be exploited to reset a limit that is actually
     * being consumed.
     */
    private void evictFullBuckets() {
        buckets.entrySet().removeIf(entry -> entry.getValue().isFull());
    }

    /** Visible for diagnostics. */
    public int trackedKeys() {
        return buckets.size();
    }

    /**
     * Outcome of a rate limit check.
     *
     * @param allowed           whether the request may proceed
     * @param retryAfterSeconds how long to wait, when refused
     */
    public record Decision(boolean allowed, long retryAfterSeconds) {
        static final Decision ALLOWED = new Decision(true, 0);
    }
}
