package com.docutrust.security.domain;

/**
 * Authorisation roles.
 *
 * <p>Deliberately coarse. Three well-understood roles that map to real
 * responsibilities beat a fine-grained permission matrix nobody can reason
 * about — and an authorisation model that cannot be reasoned about is one whose
 * gaps go unnoticed.
 */
public enum Role {

    /** Upload, sign own documents, verify, download own documents. */
    USER,

    /** Verify any submitted document and read verification reports. Cannot upload or sign. */
    VERIFIER,

    /** Manage trust configuration and certificates; read the system-wide audit log. */
    ADMIN;

    /** Spring Security authority name for this role. */
    public String authority() {
        return "ROLE_" + name();
    }
}
