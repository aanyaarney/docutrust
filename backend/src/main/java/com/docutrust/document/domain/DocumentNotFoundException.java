package com.docutrust.document.domain;

/**
 * Raised when a document does not exist, or the caller may not see it.
 *
 * <p>Both cases deliberately raise the same exception. Distinguishing "does not
 * exist" from "exists but is not yours" would let a caller enumerate which
 * document identifiers are real, which is an information disclosure in its own
 * right.
 */
public class DocumentNotFoundException extends RuntimeException {

    public DocumentNotFoundException(String documentId) {
        super("Document not accessible: " + documentId);
    }
}
