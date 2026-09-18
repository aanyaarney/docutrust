package com.docutrust.audit.domain;

/**
 * Security-relevant events recorded in the tamper-evident audit log.
 *
 * <p>The set is deliberately closed: an enum rather than free text, so that
 * every recorded event is one the system explicitly knows how to describe, and
 * so queries and dashboards cannot silently miss a new event spelled a new way.
 */
public enum AuditEventType {

    DOCUMENT_UPLOADED,
    DOCUMENT_VIEWED,
    DOCUMENT_DOWNLOADED,

    SIGN_REQUESTED,
    DOCUMENT_SIGNED,
    SIGNING_FAILED,

    SIGNATURE_VERIFIED,
    VERIFICATION_FAILED,
    TAMPERING_DETECTED,

    CERTIFICATE_VALIDATED,

    AUTHENTICATION_SUCCEEDED,
    AUTHENTICATION_FAILED,
    AUTHORIZATION_DENIED
}
