package com.docutrust.common.crypto;

/**
 * Raised when a digest cannot be computed because the underlying content could
 * not be read.
 *
 * <p>Distinct from a digest <em>mismatch</em>, which is a normal verification
 * outcome rather than an error.
 */
public class HashingException extends RuntimeException {

    public HashingException(String message, Throwable cause) {
        super(message, cause);
    }

    public HashingException(String message) {
        super(message);
    }
}
