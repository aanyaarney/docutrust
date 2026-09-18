package com.docutrust.verification.infrastructure;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A stored verification report, retrievable by its public verification ID.
 *
 * <p>Holds the report as JSON. It is written once and read whole, so shredding
 * it into columns would add schema coupling without enabling any query worth
 * having.
 *
 * <p>A stored report is a record of what verification concluded at a moment in
 * time. It is deliberately <em>not</em> a substitute for verifying again: trust
 * anchors and revocation state change, so the same document can legitimately
 * produce a different verdict later.
 */
@Entity
@Table(name = "verification_reports")
public class VerificationReportEntity {

    @Id
    @Column(name = "verification_id", length = 64, nullable = false)
    private String verificationId;

    @Column(name = "report_json", length = 1_000_000, nullable = false)
    private String reportJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected VerificationReportEntity() {
    }

    public VerificationReportEntity(String verificationId, String reportJson, Instant createdAt) {
        this.verificationId = verificationId;
        this.reportJson = reportJson;
        this.createdAt = createdAt;
    }

    public String getVerificationId() {
        return verificationId;
    }

    public String getReportJson() {
        return reportJson;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
