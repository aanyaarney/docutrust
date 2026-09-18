package com.docutrust.security.api;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.docutrust.common.api.ApiError;
import com.docutrust.common.api.CorrelationIdFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Returns 401 for unauthenticated requests to protected endpoints.
 *
 * <h2>Why this exists</h2>
 * Without an explicit entry point, Spring Security answers an anonymous request
 * to a protected endpoint with <b>403 Forbidden</b>. That is the wrong status
 * and it has a real consequence: a client cannot distinguish "your session
 * expired, sign in again" from "you are signed in but lack permission". The
 * first should send the user to the login screen; the second should not, since
 * signing in again changes nothing.
 *
 * <p>With this in place 401 means "authenticate", 403 means "authenticated but
 * not permitted", and the frontend can act on each correctly.
 *
 * <p>The response carries no detail about why authentication failed — an absent
 * token, an expired one and a forged one are indistinguishable to the caller,
 * so nothing is revealed about token handling.
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public RestAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        objectMapper.writeValue(response.getOutputStream(), ApiError.of(
                "AUTHENTICATION_REQUIRED",
                "Your session has expired or you are not signed in. Sign in and try again.",
                CorrelationIdFilter.current()));
    }
}
