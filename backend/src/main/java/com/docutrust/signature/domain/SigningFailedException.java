package com.docutrust.signature.domain;

/**
 * Raised when a signature could not be produced.
 *
 * <p>Messages must describe the operational failure (keystore unreadable, key
 * inaccessible, algorithm unsupported) and must never embed key material,
 * passwords or raw signature bytes — these messages reach logs and, in
 * sanitised form, API clients.
 */
public class SigningFailedException extends RuntimeException {

    public SigningFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningFailedException(String message) {
        super(message);
    }
}
