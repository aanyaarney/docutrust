package com.docutrust.storage.domain;

/** Raised when stored content cannot be written, read or removed. */
public class StorageException extends RuntimeException {

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }

    public StorageException(String message) {
        super(message);
    }
}
