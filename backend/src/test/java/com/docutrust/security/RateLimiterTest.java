package com.docutrust.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.docutrust.security.ratelimit.RateLimiter;

@DisplayName("Rate limiting")
class RateLimiterTest {

    @Test
    @DisplayName("Allows requests up to the burst capacity, then refuses")
    void refusesOnceBucketIsEmpty() {
        // Ten tokens, refilling at ten per minute - so roughly one every six
        // seconds. The eleventh request within the same instant must fail.
        RateLimiter limiter = new RateLimiter(10, 10);

        for (int attempt = 1; attempt <= 10; attempt++) {
            assertThat(limiter.tryAcquire("addr:203.0.113.10").allowed())
                    .as("attempt %d should be allowed", attempt)
                    .isTrue();
        }

        RateLimiter.Decision refused = limiter.tryAcquire("addr:203.0.113.10");

        assertThat(refused.allowed()).isFalse();
        // The caller must be told how long to wait, not merely that it failed.
        assertThat(refused.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("Limits are independent per key")
    void keysAreIsolated() {
        RateLimiter limiter = new RateLimiter(3, 3);

        for (int i = 0; i < 3; i++) {
            assertThat(limiter.tryAcquire("addr:198.51.100.1").allowed()).isTrue();
        }
        assertThat(limiter.tryAcquire("addr:198.51.100.1").allowed()).isFalse();

        // A different source must be unaffected: one attacker exhausting their
        // own bucket must not deny service to everybody else.
        assertThat(limiter.tryAcquire("addr:198.51.100.2").allowed()).isTrue();
    }

    @Test
    @DisplayName("A separate account gets its own budget")
    void accountsAreIsolated() {
        RateLimiter limiter = new RateLimiter(2, 2);

        assertThat(limiter.tryAcquire("user:alice").allowed()).isTrue();
        assertThat(limiter.tryAcquire("user:alice").allowed()).isTrue();
        assertThat(limiter.tryAcquire("user:alice").allowed()).isFalse();

        assertThat(limiter.tryAcquire("user:bob").allowed()).isTrue();
    }

    @Test
    @DisplayName("Tokens refill over time")
    void refillsOverTime() throws InterruptedException {
        // 120 per minute is two per second, so a 600 ms wait reliably refills
        // at least one token without making the test slow.
        RateLimiter limiter = new RateLimiter(1, 120);

        assertThat(limiter.tryAcquire("addr:test").allowed()).isTrue();
        assertThat(limiter.tryAcquire("addr:test").allowed()).isFalse();

        Thread.sleep(600);

        assertThat(limiter.tryAcquire("addr:test").allowed())
                .as("a token should have refilled after 600ms at 2/second")
                .isTrue();
    }

    @Test
    @DisplayName("Tracks each distinct key")
    void tracksDistinctKeys() {
        RateLimiter limiter = new RateLimiter(5, 5);

        limiter.tryAcquire("addr:1");
        limiter.tryAcquire("addr:2");
        limiter.tryAcquire("addr:3");

        assertThat(limiter.trackedKeys()).isEqualTo(3);
    }

    @Test
    @DisplayName("Burst capacity is respected without a window boundary to straddle")
    void noFixedWindowBurst() {
        // The failure a fixed window permits: 2N requests across a boundary.
        // A token bucket has no boundary, so exhausting the bucket and
        // immediately retrying must still refuse.
        RateLimiter limiter = new RateLimiter(5, 5);

        for (int i = 0; i < 5; i++) {
            assertThat(limiter.tryAcquire("addr:burst").allowed()).isTrue();
        }
        for (int i = 0; i < 5; i++) {
            assertThat(limiter.tryAcquire("addr:burst").allowed())
                    .as("no second burst should be available immediately")
                    .isFalse();
        }
    }
}
