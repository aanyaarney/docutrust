package com.docutrust.security.api;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.docutrust.common.api.ApiError;
import com.docutrust.common.api.CorrelationIdFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Returns 403 when an authenticated caller lacks the required role.
 *
 * <h2>Why this is registered explicitly</h2>
 * The distinction between 401 and 403 is load-bearing for the client: a 401
 * means "sign in again" and sends the user to the login screen, while a 403
 * means "you are signed in but may not do this" and must not. Relying on
 * framework defaults to get that split right leaves it implicit and easy to
 * break; registering both handlers makes the contract explicit and testable.
 *
 * <p>The denial is logged with the correlation ID, since repeated authorisation
 * failures from one account are worth noticing. The response itself says
 * nothing about which role would have been sufficient — that would map out the
 * permission model for an attacker probing endpoints.
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger(RestAccessDeniedHandler.class);

    private final ObjectMapper objectMapper;

    public RestAccessDeniedHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        log.warn("Access denied: {} {} [{}]",
                request.getMethod(), request.getRequestURI(), CorrelationIdFilter.current());

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getOutputStream(), ApiError.of(
                "ACCESS_DENIED",
                "You do not have permission to perform this action.",
                CorrelationIdFilter.current()));
    }
}
