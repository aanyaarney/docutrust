package com.docutrust.audit.api;

import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.audit.domain.ChainVerificationResult;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * System-wide audit access.
 *
 * <p>Administrator-only. The audit log records who did what to which document
 * across every account, so it is more sensitive than the documents themselves.
 * Per-document history remains available to a document's owner through
 * {@code /api/v1/documents/{id}/audit}.
 */
@RestController
@RequestMapping("/api/v1/admin/audit")
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/integrity")
    @Operation(summary = "Re-compute the audit hash chain and report whether it is intact")
    public ChainVerificationResult integrity() {
        return auditService.verifyChain();
    }

    @GetMapping("/recent")
    @Operation(summary = "Most recent audit events")
    public List<AuditRecord> recent() {
        return auditService.recentActivity();
    }
}
