package com.docutrust.document.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import com.docutrust.document.domain.SignatureState;

/** Metadata for an uploaded document. The PDF bytes themselves live in object storage. */
@Entity
@Table(name = "documents")
public class DocumentEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "file_name", length = 512, nullable = false)
    private String fileName;

    @Column(name = "owner_id", length = 36, nullable = false)
    private String ownerId;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    /** SHA-256 of the original upload, lower-case hex. */
    @Column(name = "sha256", length = 64, nullable = false)
    private String sha256;

    @Column(name = "page_count")
    private Integer pageCount;

    @Column(name = "content_type", length = 128, nullable = false)
    private String contentType;

    @Enumerated(EnumType.STRING)
    @Column(name = "signature_state", length = 32, nullable = false)
    private SignatureState signatureState;

    @Column(name = "uploaded_at", nullable = false)
    private Instant uploadedAt;

    protected DocumentEntity() {
    }

    public DocumentEntity(String id, String fileName, String ownerId, long sizeBytes,
                          String sha256, Integer pageCount, String contentType,
                          SignatureState signatureState, Instant uploadedAt) {
        this.id = id;
        this.fileName = fileName;
        this.ownerId = ownerId;
        this.sizeBytes = sizeBytes;
        this.sha256 = sha256;
        this.pageCount = pageCount;
        this.contentType = contentType;
        this.signatureState = signatureState;
        this.uploadedAt = uploadedAt;
    }

    public String getId() {
        return id;
    }

    public String getFileName() {
        return fileName;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }

    public String getSha256() {
        return sha256;
    }

    public Integer getPageCount() {
        return pageCount;
    }

    public String getContentType() {
        return contentType;
    }

    public SignatureState getSignatureState() {
        return signatureState;
    }

    public void setSignatureState(SignatureState signatureState) {
        this.signatureState = signatureState;
    }

    public Instant getUploadedAt() {
        return uploadedAt;
    }
}
