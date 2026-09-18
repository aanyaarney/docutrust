package com.docutrust.security.application;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import com.docutrust.common.config.DocuTrustProperties;
import com.docutrust.security.domain.Role;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Issues and validates JSON Web Tokens.
 *
 * <h2>Secret handling</h2>
 * HS256 requires at least 256 bits of key material. A short or guessable secret
 * lets anyone mint tokens for any user, so a weak secret is refused rather than
 * padded to length.
 *
 * <p>Under the {@code local} profile a random secret is generated at startup if
 * none is configured, which keeps first-run development frictionless. The
 * consequence — every restart invalidates existing tokens — is stated in the
 * log. Outside {@code local}, a missing secret is a startup failure: silently
 * inventing one in production would mean tokens survive only until the next
 * deployment, and would hide a misconfiguration that matters.
 */
@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    /** HS256 requires a 256-bit key. Anything shorter is rejected by the library. */
    private static final int MINIMUM_SECRET_BYTES = 32;

    private static final String ROLE_CLAIM = "role";
    private static final String NAME_CLAIM = "name";

    private final SecretKey signingKey;
    private final String issuer;
    private final long ttlSeconds;

    public JwtService(DocuTrustProperties properties, Environment environment) {
        DocuTrustProperties.Jwt config = properties.getJwt();
        this.issuer = config.getIssuer();
        this.ttlSeconds = config.getTtlMinutes() * 60L;
        this.signingKey = resolveKey(config, environment);
    }

    private SecretKey resolveKey(DocuTrustProperties.Jwt config, Environment environment) {
        String secret = config.getSecret();

        if (secret != null && !secret.isBlank()) {
            byte[] material = secret.getBytes(StandardCharsets.UTF_8);
            if (material.length < MINIMUM_SECRET_BYTES) {
                throw new IllegalStateException(
                        "DOCUTRUST_JWT_SECRET must be at least " + MINIMUM_SECRET_BYTES
                                + " bytes. A short secret can be brute-forced, allowing anyone to "
                                + "mint valid tokens for any account. Generate one with: "
                                + "openssl rand -base64 48");
            }
            return Keys.hmacShaKeyFor(material);
        }

        boolean local = java.util.List.of(environment.getActiveProfiles()).contains("local")
                || (environment.getActiveProfiles().length == 0
                    && java.util.List.of(environment.getDefaultProfiles()).contains("local"));

        if (!local) {
            throw new IllegalStateException(
                    "DOCUTRUST_JWT_SECRET is not set. DocuTrust will not generate a signing secret "
                            + "outside local development, because a secret that changes on every "
                            + "restart hides a real misconfiguration.");
        }

        byte[] generated = new byte[48];
        new SecureRandom().nextBytes(generated);
        log.warn("No DOCUTRUST_JWT_SECRET configured; generated a random one for this run. "
                + "All issued tokens become invalid when the application restarts.");
        return Keys.hmacShaKeyFor(generated);
    }

    /** Issues a token for an authenticated user. */
    public String issueToken(String userId, String email, String displayName, Role role) {
        Instant now = Instant.now();

        return Jwts.builder()
                .subject(userId)
                .issuer(issuer)
                .claim("email", email)
                .claim(NAME_CLAIM, displayName)
                .claim(ROLE_CLAIM, role.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .id(newTokenId())
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a token and returns its claims.
     *
     * @throws JwtException if the signature, issuer or expiry check fails
     */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Role roleOf(Claims claims) {
        return Role.valueOf(claims.get(ROLE_CLAIM, String.class));
    }

    public String displayNameOf(Claims claims) {
        return claims.get(NAME_CLAIM, String.class);
    }

    public long ttlSeconds() {
        return ttlSeconds;
    }

    /** Unique token identifier, enabling future revocation lists. */
    private String newTokenId() {
        byte[] bytes = new byte[12];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
