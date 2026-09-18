package com.docutrust.verification.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import com.docutrust.verification.domain.VerificationVerdict;

/**
 * A stored verification outcome, retrievable later by its public
 * {@code verificationId}.
 *
 * <p>Persisting the outcome lets a report be re-opened and shared without
 * re-uploading the document. It is a record of what verification concluded at a
 * point in time — not a substitute for verifying again, since trust anchors and
 * revocation state change.
 */
@Entity
@Table(name = "verification_records")
public class VerificationRecordEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    /** Public, shareable identifier, e.g. {@code VER-A1B2C3D4E5F6}. */
    @Column(name = "verification_id", length = 64, nullable = false, unique = true)
    private String verificationId;

    @Column(name = "document_id", length = 36)
    private String documentId;

    @Column(name = "requested_by", length = 36)
    private String requestedBy;

    @Column(name = "file_name", length = 512)
    private String fileName;

    @Column(name = "document_sha256", length = 64, nullable = false)
    private String documentSha256;

    @Enumerated(EnumType.STRING)
    @Column(name = "verdict", length = 32, nullable = false)
    private VerificationVerdict verdict;

    @Column(name = "signature_count", nullable = false)
    private int signatureCount;

    @Column(name = "tampering_detected", nullable = false)
    private boolean tamperingDetected;

    @Column(name = "report_json", length = 16384)
    private String reportJson;

    @Column(name = "verified_at", nullable = false)
    private Instant verifiedAt;

    protected VerificationRecordEntity() {
    }

    public VerificationRecordEntity(String id, String verificationId, String documentId,
                                    String requestedBy, String fileName, String documentSha256,
                                    VerificationVerdict verdict, int signatureCount,
                                    boolean tamperingDetected, String reportJson,
                                    Instant verifiedAt) {
        this.id = id;
        this.verificationId = verificationId;
        this.documentId = documentId;
        this.requestedBy = requestedBy;
        this.fileName = fileName;
        this.documentSha256 = documentSha256;
        this.verdict = verdict;
        this.signatureCount = signatureCount;
        this.tamperingDetected = tamperingDetected;
        this.reportJson = reportJson;
        this.verifiedAt = verifiedAt;
    }

    public String getId() {
        return id;
    }

    public String getVerificationId() {
        return verificationId;
    }

    public String getDocumentId() {
        return documentId;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public String getFileName() {
        return fileName;
    }

    public String getDocumentSha256() {
        return documentSha256;
    }

    public VerificationVerdict getVerdict() {
        return verdict;
    }

    public int getSignatureCount() {
        return signatureCount;
    }

    public boolean isTamperingDetected() {
        return tamperingDetected;
    }

    public String getReportJson() {
        return reportJson;
    }

    public Instant getVerifiedAt() {
        return verifiedAt;
    }
}
