package com.docutrust.security.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.common.api.ApiError;
import com.docutrust.common.api.CorrelationIdFilter;
import com.docutrust.security.application.JwtService;
import com.docutrust.security.domain.AuthenticatedUser;
import com.docutrust.security.infrastructure.UserEntity;
import com.docutrust.security.infrastructure.UserRepository;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** Authentication endpoints. */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuditService auditService;

    public AuthController(UserRepository users, PasswordEncoder passwordEncoder,
                          JwtService jwtService, AuditService auditService) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.auditService = auditService;
    }

    public record LoginRequest(
            @NotBlank @Email String email,
            @NotBlank String password) {
    }

    public record LoginResponse(
            String token, String tokenType, long expiresInSeconds,
            String userId, String email, String displayName, String role) {
    }

    @PostMapping("/login")
    @Operation(summary = "Exchange credentials for a bearer token")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {

        UserEntity user = users.findByEmail(request.email().toLowerCase()).orElse(null);

        // The password is verified even when no such user exists, against a
        // dummy hash. Returning early would make a non-existent account
        // measurably faster to reject than a wrong password, letting an
        // attacker enumerate valid email addresses by timing alone.
        boolean passwordMatches = passwordEncoder.matches(
                request.password(),
                user != null ? user.getPasswordHash() : DUMMY_HASH);

        if (user == null || !passwordMatches || !user.isEnabled()) {
            // One message for every failure mode, for the same reason.
            log.info("Failed login attempt [{}]", CorrelationIdFilter.current());
            auditService.record(AuditEventType.AUTHENTICATION_FAILED, null, null,
                    "Failed login attempt");

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiError.of("AUTHENTICATION_FAILED",
                            "Incorrect email address or password.",
                            CorrelationIdFilter.current()));
        }

        String token = jwtService.issueToken(
                user.getId(), user.getEmail(), user.getDisplayName(), user.getRole());

        auditService.record(AuditEventType.AUTHENTICATION_SUCCEEDED, null, user.getId(),
                "Signed in");

        return ResponseEntity.ok(new LoginResponse(
                token, "Bearer", jwtService.ttlSeconds(),
                user.getId(), user.getEmail(), user.getDisplayName(), user.getRole().name()));
    }

    @GetMapping("/me")
    @Operation(summary = "Describe the currently authenticated user")
    public AuthenticatedUser me(@AuthenticationPrincipal AuthenticatedUser user) {
        return user;
    }

    /**
     * A real BCrypt hash of a value no one knows, used purely so that failed
     * lookups cost the same as failed password checks.
     */
    private static final String DUMMY_HASH =
            "$2a$12$C6UzMDM.H6dfI/f/IKcEe.5vJ5s1sHZ5dLnQ0CxXJYVLpQZ8KqZ0i";
}
