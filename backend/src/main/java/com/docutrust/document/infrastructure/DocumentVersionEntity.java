package com.docutrust.document.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One stored revision of a document.
 *
 * <p>Version 0 is the original upload. Each signature produces a new version
 * rather than overwriting the previous one, so the full history stays
 * retrievable and a signed document can always be compared against what came
 * before it.
 */
@Entity
@Table(name = "document_versions")
public class DocumentVersionEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "document_id", length = 36, nullable = false)
    private String documentId;

    @Column(name = "version_number", nullable = false)
    private int versionNumber;

    /** Key locating the bytes in object storage. */
    @Column(name = "storage_key", length = 1024, nullable = false)
    private String storageKey;

    @Column(name = "sha256", length = 64, nullable = false)
    private String sha256;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "signed", nullable = false)
    private boolean signed;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected DocumentVersionEntity() {
    }

    public DocumentVersionEntity(String id, String documentId, int versionNumber, String storageKey,
                                 String sha256, long sizeBytes, boolean signed, Instant createdAt) {
        this.id = id;
        this.documentId = documentId;
        this.versionNumber = versionNumber;
        this.storageKey = storageKey;
        this.sha256 = sha256;
        this.sizeBytes = sizeBytes;
        this.signed = signed;
        this.createdAt = createdAt;
    }

    public String getId() {
        return id;
    }

    public String getDocumentId() {
        return documentId;
    }

    public int getVersionNumber() {
        return versionNumber;
    }

    public String getStorageKey() {
        return storageKey;
    }

    public String getSha256() {
        return sha256;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public boolean isSigned() {
        return signed;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
