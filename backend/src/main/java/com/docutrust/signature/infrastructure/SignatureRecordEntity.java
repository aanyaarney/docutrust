package com.docutrust.signature.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A record that a signature was applied.
 *
 * <p>Holds descriptive facts only. The authoritative signature lives inside the
 * signed PDF itself — this row is an index for listing and reporting, never a
 * substitute for verifying the document. Trusting this row instead of the file
 * would be exactly the "store a hash in the database and call it signed"
 * anti-pattern the specification forbids.
 */
@Entity
@Table(name = "signature_records")
public class SignatureRecordEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "document_id", length = 36, nullable = false)
    private String documentId;

    @Column(name = "document_version_id", length = 36, nullable = false)
    private String documentVersionId;

    @Column(name = "signer_user_id", length = 36)
    private String signerUserId;

    @Column(name = "signer_common_name", length = 512)
    private String signerCommonName;

    @Column(name = "certificate_subject", length = 1024)
    private String certificateSubject;

    @Column(name = "certificate_issuer", length = 1024)
    private String certificateIssuer;

    @Column(name = "certificate_serial", length = 128)
    private String certificateSerial;

    @Column(name = "signature_algorithm", length = 64, nullable = false)
    private String signatureAlgorithm;

    @Column(name = "digest_algorithm", length = 64, nullable = false)
    private String digestAlgorithm;

    @Column(name = "signature_format", length = 64, nullable = false)
    private String signatureFormat;

    @Column(name = "provider_name", length = 64, nullable = false)
    private String providerName;

    @Column(name = "reason", length = 512)
    private String reason;

    @Column(name = "location", length = 512)
    private String location;

    @Column(name = "signed_at", nullable = false)
    private Instant signedAt;

    protected SignatureRecordEntity() {
    }

    public SignatureRecordEntity(String id, String documentId, String documentVersionId,
                                 String signerUserId, String signerCommonName,
                                 String certificateSubject, String certificateIssuer,
                                 String certificateSerial, String signatureAlgorithm,
                                 String digestAlgorithm, String signatureFormat,
                                 String providerName, String reason, String location,
                                 Instant signedAt) {
        this.id = id;
        this.documentId = documentId;
        this.documentVersionId = documentVersionId;
        this.signerUserId = signerUserId;
        this.signerCommonName = signerCommonName;
        this.certificateSubject = certificateSubject;
        this.certificateIssuer = certificateIssuer;
        this.certificateSerial = certificateSerial;
        this.signatureAlgorithm = signatureAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.signatureFormat = signatureFormat;
        this.providerName = providerName;
        this.reason = reason;
        this.location = location;
        this.signedAt = signedAt;
    }

    public String getId() {
        return id;
    }

    public String getDocumentId() {
        return documentId;
    }

    public String getDocumentVersionId() {
        return documentVersionId;
    }

    public String getSignerUserId() {
        return signerUserId;
    }

    public String getSignerCommonName() {
        return signerCommonName;
    }

    public String getCertificateSubject() {
        return certificateSubject;
    }

    public String getCertificateIssuer() {
        return certificateIssuer;
    }

    public String getCertificateSerial() {
        return certificateSerial;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public String getSignatureFormat() {
        return signatureFormat;
    }

    public String getProviderName() {
        return providerName;
    }

    public String getReason() {
        return reason;
    }

    public String getLocation() {
        return location;
    }

    public Instant getSignedAt() {
        return signedAt;
    }
}
