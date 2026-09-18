package com.docutrust.security.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import com.docutrust.security.domain.Role;

/**
 * A user account.
 *
 * <p>{@code passwordHash} holds a BCrypt hash produced by Spring Security's
 * {@link org.springframework.security.crypto.password.PasswordEncoder}. Plain
 * passwords are never stored, never logged, and never returned by any API.
 */
@Entity
@Table(name = "users")
public class UserEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "email", length = 255, nullable = false, unique = true)
    private String email;

    @Column(name = "display_name", length = 255, nullable = false)
    private String displayName;

    @Column(name = "password_hash", length = 255, nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", length = 32, nullable = false)
    private Role role;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected UserEntity() {
        // Required by JPA.
    }

    public UserEntity(String id, String email, String displayName,
                      String passwordHash, Role role, Instant createdAt) {
        this.id = id;
        this.email = email;
        this.displayName = displayName;
        this.passwordHash = passwordHash;
        this.role = role;
        this.createdAt = createdAt;
        this.enabled = true;
    }

    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Role getRole() {
        return role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Deliberately excludes {@code passwordHash}.
     *
     * <p>Entities end up in log lines and exception messages by accident.
     * Keeping the hash out of {@code toString} removes one route by which
     * credential material leaks into logs.
     */
    @Override
    public String toString() {
        return "UserEntity{id=%s, email=%s, role=%s}".formatted(id, email, role);
    }
}
