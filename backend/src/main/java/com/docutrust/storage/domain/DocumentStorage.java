package com.docutrust.storage.domain;

import java.io.InputStream;

/**
 * Stores and retrieves document bytes.
 *
 * <p>PDFs — originals, each signed version, and generated reports — live here
 * rather than in PostgreSQL. Large binaries in a relational database bloat
 * backups, slow replication, and push multi-megabyte blobs through the
 * connection pool for every read.
 *
 * <p>Implementations: {@code FilesystemDocumentStorage} (local development),
 * {@code MinioDocumentStorage} (S3-compatible). S3, GCS and Azure Blob are
 * drop-in future implementations behind this same interface.
 */
public interface DocumentStorage {

    /**
     * Stores content under {@code key}, replacing anything already there.
     *
     * @param key         storage key, e.g. {@code documents/<id>/original.pdf}
     * @param content     bytes to store; the stream is consumed but not closed
     * @param contentType MIME type to record
     * @param sizeBytes   content length, required by object stores for streaming
     */
    void store(String key, InputStream content, String contentType, long sizeBytes);

    /**
     * Opens a stream over stored content. The caller must close it.
     *
     * @throws StorageException if the key does not exist
     */
    InputStream retrieve(String key);

    /** Reads stored content fully into memory. Only for content known to be small. */
    byte[] retrieveAllBytes(String key);

    boolean exists(String key);

    /** Deletes the object, or does nothing if it is already absent. */
    void delete(String key);

    /** Identifier for diagnostics and health reporting. */
    String backendName();
}
