package com.docutrust.verification.application;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.common.observability.DocuTrustMetrics;
import com.docutrust.document.application.PdfUploadValidator;
import com.docutrust.security.domain.AuthenticatedUser;
import com.docutrust.verification.domain.VerificationReport;
import com.docutrust.verification.domain.VerificationVerdict;
import com.docutrust.verification.infrastructure.VerificationRecordEntity;
import com.docutrust.verification.infrastructure.VerificationRecordRepository;
import com.docutrust.verification.infrastructure.VerificationReportEntity;
import com.docutrust.verification.infrastructure.VerificationReportRepository;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Runs verification and records its outcome.
 *
 * <p>Note what this does <em>not</em> do: it never rejects a submission for
 * being unsigned, tampered or untrusted. Those are verification results, and
 * reporting them accurately is the product. The only inputs turned away are
 * files too large to process or not PDFs at all.
 */
@Service
public class VerificationApplicationService {

    private static final Logger log = LoggerFactory.getLogger(VerificationApplicationService.class);

    private final VerificationService verificationService;
    private final VerificationRecordRepository records;
    private final VerificationReportRepository reports;
    private final PdfUploadValidator validator;
    private final AuditService auditService;
    private final DocuTrustMetrics metrics;
    private final ObjectMapper objectMapper;
    private final HtmlReportRenderer htmlRenderer = new HtmlReportRenderer();

    public VerificationApplicationService(VerificationService verificationService,
                                          VerificationRecordRepository records,
                                          VerificationReportRepository reports,
                                          PdfUploadValidator validator,
                                          AuditService auditService,
                                          DocuTrustMetrics metrics,
                                          ObjectMapper objectMapper) {
        this.verificationService = verificationService;
        this.records = records;
        this.reports = reports;
        this.validator = validator;
        this.auditService = auditService;
        this.metrics = metrics;
        this.objectMapper = objectMapper;
    }

    /**
     * Verifies a submitted document and stores the outcome.
     *
     * @param documentId optional identifier when verifying a stored document
     */
    public VerificationReport verify(byte[] content, String fileName,
                                     String documentId, AuthenticatedUser user) {

        String safeName = validator.sanitiseFilename(fileName);

        // Cryptographic work happens outside any transaction.
        long startedAt = System.nanoTime();
        VerificationReport report = verificationService.verify(content, safeName);
        metrics.recordVerification(
                report.verdict(),
                report.hasProvenTampering(),
                Duration.ofNanos(System.nanoTime() - startedAt));

        persist(report, documentId, user);
        storeReport(report);
        recordAudit(report, documentId, user);

        return report;
    }

    /**
     * Stores the full report so it can be re-opened by its verification ID.
     *
     * <p>Serialisation failure must not fail the verification itself. The
     * verdict is the product; the stored copy is a convenience, and losing it
     * is not a reason to withhold an answer the caller already has.
     */
    @Transactional
    protected void storeReport(VerificationReport report) {
        try {
            String json = objectMapper.writeValueAsString(report);
            reports.save(new VerificationReportEntity(
                    report.verificationId(), json, report.verifiedAt()));
        } catch (Exception e) {
            log.warn("Could not store verification report {}: {}",
                    report.verificationId(), e.getClass().getSimpleName());
        }
    }

    /** The stored report as JSON, if one exists. */
    @Transactional(readOnly = true)
    public Optional<String> reportJson(String verificationId) {
        return reports.findByVerificationId(verificationId)
                .map(VerificationReportEntity::getReportJson);
    }

    /** The stored report rendered as a standalone HTML document. */
    @Transactional(readOnly = true)
    public Optional<String> reportHtml(String verificationId) {
        return reports.findByVerificationId(verificationId).map(entity -> {
            try {
                VerificationReport report =
                        objectMapper.readValue(entity.getReportJson(), VerificationReport.class);
                return htmlRenderer.render(report);
            } catch (Exception e) {
                log.warn("Could not render report {}: {}",
                        verificationId, e.getClass().getSimpleName());
                return null;
            }
        });
    }

    @Transactional
    protected void persist(VerificationReport report, String documentId, AuthenticatedUser user) {
        records.save(new VerificationRecordEntity(
                UUID.randomUUID().toString(),
                report.verificationId(),
                documentId,
                user == null ? null : user.id(),
                report.fileName(),
                report.documentSha256(),
                report.verdict(),
                report.signatureCount(),
                report.hasProvenTampering(),
                null,
                report.verifiedAt()));
    }

    private void recordAudit(VerificationReport report, String documentId, AuthenticatedUser user) {
        String userId = user == null ? null : user.id();

        // Tampering gets its own event type so it can be alerted on directly
        // rather than inferred from a generic failure.
        if (report.hasProvenTampering()) {
            log.warn("Tampering detected: verificationId={} verdict={}",
                    report.verificationId(), report.verdict());
            auditService.record(AuditEventType.TAMPERING_DETECTED, documentId, userId,
                    "Tampering detected during verification " + report.verificationId());
            return;
        }

        if (report.verdict().isFailure()) {
            auditService.record(AuditEventType.VERIFICATION_FAILED, documentId, userId,
                    "Verification " + report.verificationId() + " returned " + report.verdict());
            return;
        }

        auditService.record(AuditEventType.SIGNATURE_VERIFIED, documentId, userId,
                "Verification " + report.verificationId() + " returned " + report.verdict());
    }

    @Transactional(readOnly = true)
    public Optional<VerificationRecordEntity> findByVerificationId(String verificationId) {
        return records.findByVerificationId(verificationId);
    }

    @Transactional(readOnly = true)
    public long countByVerdict(VerificationVerdict verdict) {
        return records.countByVerdict(verdict);
    }

    @Transactional(readOnly = true)
    public long countTampering() {
        return records.countByTamperingDetectedTrue();
    }
}
