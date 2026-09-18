package com.docutrust.document.domain;

/**
 * Raised when an uploaded file is rejected.
 *
 * <p>Messages are written to be shown to users directly, so they must explain
 * the problem without revealing anything about server internals.
 */
public class UnsupportedDocumentException extends RuntimeException {

    public UnsupportedDocumentException(String message) {
        super(message);
    }
}
