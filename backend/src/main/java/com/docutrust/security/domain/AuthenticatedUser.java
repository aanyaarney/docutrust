package com.docutrust.security.domain;

/**
 * The authenticated caller, as established from a validated token.
 *
 * <p>Carries no credential material — no password hash, no raw token — so that
 * it is safe to hold in the security context and to reference in logs.
 */
public record AuthenticatedUser(String id, String email, String displayName, Role role) {

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    public boolean canUploadAndSign() {
        return role == Role.USER || role == Role.ADMIN;
    }
}
