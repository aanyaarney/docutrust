package com.docutrust.security.ratelimit;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.docutrust.common.api.ApiError;
import com.docutrust.common.api.CorrelationIdFilter;
import com.docutrust.common.config.DocuTrustProperties;
import com.docutrust.security.domain.AuthenticatedUser;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Applies rate limits to the endpoints worth protecting.
 *
 * <h2>Two different limits, for two different attacks</h2>
 *
 * <p><b>Authentication</b> is limited by source address, tightly. The attack is
 * credential stuffing: many guesses against many accounts. Limiting per account
 * would not help, since an attacker spreads guesses across accounts precisely to
 * avoid that. The limit must therefore bind to the thing the attacker actually
 * has to spend — network origin.
 *
 * <p><b>Signing and verification</b> are limited per authenticated user, more
 * loosely. The attack here is resource exhaustion: each request performs RSA
 * operations and parses a PDF, so an authenticated user could otherwise consume
 * unbounded CPU. A per-user limit is right because the work is attributable to
 * an account.
 *
 * <p>Everything else is unlimited. Listing documents is cheap, and a limit that
 * fires on ordinary use trains people to ignore it.
 *
 * <h2>Ordering</h2>
 * This filter runs before authentication so that unauthenticated login attempts
 * are limited. For authenticated endpoints the security context is already
 * populated by the time the request reaches them, so the user key is available —
 * where it is not, the address is used instead.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final RateLimiter authenticationLimiter;
    private final RateLimiter expensiveOperationLimiter;
    private final ObjectMapper objectMapper;
    private final boolean enabled;

    public RateLimitFilter(DocuTrustProperties properties, ObjectMapper objectMapper) {
        DocuTrustProperties.RateLimit config = properties.getRateLimit();
        this.enabled = config.isEnabled();
        this.objectMapper = objectMapper;

        this.authenticationLimiter = new RateLimiter(
                config.getLoginBurst(), config.getLoginPerMinute());
        this.expensiveOperationLimiter = new RateLimiter(
                config.getExpensiveBurst(), config.getExpensivePerMinute());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (!enabled) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        RateLimiter limiter = limiterFor(path, request.getMethod());

        if (limiter == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = keyFor(request, limiter);
        RateLimiter.Decision decision = limiter.tryAcquire(key);

        if (decision.allowed()) {
            filterChain.doFilter(request, response);
            return;
        }

        // Log that a limit fired, but never the key itself: for the
        // authentication limiter the key is a source address, which is personal
        // data, and for the operation limiter it is a user identifier.
        log.warn("Rate limit exceeded for {} {} [{}]",
                request.getMethod(), path, CorrelationIdFilter.current());

        writeRejection(response, decision.retryAfterSeconds());
    }

    private RateLimiter limiterFor(String path, String method) {
        if (path.startsWith("/api/v1/auth/login")) {
            return authenticationLimiter;
        }
        if (!"POST".equalsIgnoreCase(method)) {
            return null;
        }
        // Signing and verification both perform cryptographic work on a PDF.
        if (path.startsWith("/api/v1/verification") || path.endsWith("/sign")) {
            return expensiveOperationLimiter;
        }
        return null;
    }

    /**
     * Keys authenticated requests by user, and anonymous ones by address.
     */
    private String keyFor(HttpServletRequest request, RateLimiter limiter) {
        if (limiter == expensiveOperationLimiter) {
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.getPrincipal() instanceof AuthenticatedUser user) {
                return "user:" + user.id();
            }
        }
        return "addr:" + clientAddress(request);
    }

    /**
     * Best-effort client address.
     *
     * <p>{@code X-Forwarded-For} is honoured only because this application is
     * expected to sit behind a reverse proxy. The header is client-controlled
     * and trivially spoofed when no proxy strips it, so a deployment that
     * exposes the application directly must not trust it — in that case the
     * proxy-aware branch should be disabled. Only the first entry is taken, and
     * it is length-capped so a huge header cannot be used to grow the key space.
     */
    private String clientAddress(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String first = forwarded.split(",")[0].trim();
            if (!first.isEmpty()) {
                return first.length() > 45 ? first.substring(0, 45) : first;
            }
        }
        String remote = request.getRemoteAddr();
        return remote == null ? "unknown" : remote;
    }

    private void writeRejection(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Retry-After", Long.toString(retryAfterSeconds));

        ApiError error = ApiError.of(
                "RATE_LIMIT_EXCEEDED",
                "Too many requests. Wait " + retryAfterSeconds + " seconds and try again.",
                CorrelationIdFilter.current());

        objectMapper.writeValue(response.getOutputStream(), error);
    }
}
