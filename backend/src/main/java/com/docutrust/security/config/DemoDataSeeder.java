package com.docutrust.security.config;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.docutrust.common.config.DocuTrustProperties;
import com.docutrust.security.domain.Role;
import com.docutrust.security.infrastructure.UserEntity;
import com.docutrust.security.infrastructure.UserRepository;

/**
 * Creates demonstration accounts under the {@code local} profile.
 *
 * <h2>Why no password appears in this file</h2>
 * Passwords come from the environment. A credential committed to source is
 * a credential published to everyone with repository access, and it survives
 * in history even after being "removed" (specification sections 5.1 and 30).
 *
 * <p>If no password is configured, a random one is generated and printed once
 * to the startup log. That keeps a first clone usable without a hardcoded
 * secret, and the password changes on every restart. The printing is
 * acceptable only because the account is local, ephemeral and demonstrative;
 * the seeder is restricted to the {@code local} profile so this can never
 * happen in a deployed environment.
 */
@Component
@Profile("local")
public class DemoDataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final DocuTrustProperties properties;

    public DemoDataSeeder(UserRepository users, PasswordEncoder passwordEncoder,
                          DocuTrustProperties properties) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        DocuTrustProperties.Demo demo = properties.getDemo();
        if (!demo.isSeedEnabled()) {
            return;
        }

        String userPassword = seed(demo.getUserEmail(), "Demo User", demo.getUserPassword(), Role.USER);
        String adminPassword = seed(demo.getAdminEmail(), "Demo Administrator",
                demo.getAdminPassword(), Role.ADMIN);

        if (userPassword != null || adminPassword != null) {
            log.warn("""

                    ============================================================
                     DEMONSTRATION ACCOUNTS (local profile only)
                     These passwords were generated for this run and change on
                     every restart. Set DOCUTRUST_DEMO_USER_PASSWORD and
                     DOCUTRUST_DEMO_ADMIN_PASSWORD in .env for stable ones.

                       {}  /  {}
                       {}  /  {}
                    ============================================================""",
                    demo.getUserEmail(), userPassword == null ? "(from environment)" : userPassword,
                    demo.getAdminEmail(), adminPassword == null ? "(from environment)" : adminPassword);
        }
    }

    /**
     * Creates the account if absent.
     *
     * @return the generated password, or {@code null} if one was configured
     */
    private String seed(String email, String displayName, String configuredPassword, Role role) {
        if (email == null || email.isBlank() || users.existsByEmail(email.toLowerCase())) {
            return null;
        }

        boolean generated = configuredPassword == null || configuredPassword.isBlank();
        String password = generated ? generatePassword() : configuredPassword;

        users.save(new UserEntity(
                UUID.randomUUID().toString(),
                email.toLowerCase(),
                displayName,
                passwordEncoder.encode(password),
                role,
                Instant.now()));

        log.info("Seeded demonstration account {} with role {}", email, role);
        return generated ? password : null;
    }

    /** 18 bytes of secure randomness, URL-safe encoded. */
    private String generatePassword() {
        byte[] bytes = new byte[18];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
