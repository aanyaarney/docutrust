package com.docutrust.certificate.devpki;

/** Raised when the development PKI cannot be generated or persisted. */
public class DevPkiException extends RuntimeException {

    public DevPkiException(String message, Throwable cause) {
        super(message, cause);
    }

    public DevPkiException(String message) {
        super(message);
    }
}
