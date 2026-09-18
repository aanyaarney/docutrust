package com.docutrust.common.api;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HexFormat;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Assigns every request a correlation identifier.
 *
 * <p>The identifier flows into the logging context, the audit record, and the
 * error response, so a user-reported failure can be traced to exactly the log
 * lines and audit entries it produced.
 *
 * <p>A client-supplied {@code X-Correlation-Id} is accepted for tracing across
 * services, but is length-limited and stripped of anything outside a safe
 * character set. An unsanitised value would be a log-injection vector: newlines
 * in a header can forge entire log lines.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Correlation-Id";
    public static final String MDC_KEY = "correlationId";

    private static final int MAX_LENGTH = 64;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String correlationId = sanitise(request.getHeader(HEADER));
        if (correlationId == null) {
            correlationId = generate();
        }

        MDC.put(MDC_KEY, correlationId);
        response.setHeader(HEADER, correlationId);
        request.setAttribute(MDC_KEY, correlationId);

        try {
            filterChain.doFilter(request, response);
        } finally {
            // Threads are pooled; leaving the value set would attach this
            // request's identifier to an unrelated later request.
            MDC.remove(MDC_KEY);
        }
    }

    /** Keeps only characters that cannot forge log structure. */
    private String sanitise(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.length() > MAX_LENGTH ? value.substring(0, MAX_LENGTH) : value;
        String cleaned = trimmed.replaceAll("[^A-Za-z0-9._-]", "");
        return cleaned.isBlank() ? null : cleaned;
    }

    private String generate() {
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    /** The current request's correlation identifier, or {@code "unknown"}. */
    public static String current() {
        String value = MDC.get(MDC_KEY);
        return value == null ? "unknown" : value;
    }
}
