package com.docutrust.verification.api;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditRecord;
import com.docutrust.common.config.SigningMaterial;
import com.docutrust.document.application.DocumentPersistenceService;
import com.docutrust.security.domain.AuthenticatedUser;
import com.docutrust.verification.application.VerificationApplicationService;
import com.docutrust.verification.domain.VerificationVerdict;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/** Aggregated figures for the dashboard. */
@RestController
@RequestMapping("/api/v1/dashboard")
@Tag(name = "Dashboard")
public class DashboardController {

    private final DocumentPersistenceService documents;
    private final VerificationApplicationService verifications;
    private final AuditService auditService;
    private final SigningMaterial signingMaterial;

    public DashboardController(DocumentPersistenceService documents,
                               VerificationApplicationService verifications,
                               AuditService auditService,
                               SigningMaterial signingMaterial) {
        this.documents = documents;
        this.verifications = verifications;
        this.auditService = auditService;
        this.signingMaterial = signingMaterial;
    }

    /**
     * @param auditChainIntact whether the audit hash chain recomputes correctly
     * @param signingMaterialDescription what key material this instance is using
     * @param developmentPki  whether signing uses an ephemeral development PKI;
     *                        surfaced so a demonstration can never be mistaken
     *                        for a trustworthy deployment
     */
    public record DashboardSummary(
            long documentsUploaded,
            long documentsSigned,
            long validVerifications,
            long untrustedVerifications,
            long failedVerifications,
            long tamperingDetected,
            int trustAnchors,
            boolean auditChainIntact,
            String auditChainExplanation,
            String signingMaterialDescription,
            boolean developmentPki,
            List<AuditRecord> recentActivity) {
    }

    @GetMapping("/summary")
    @Operation(summary = "Aggregated counts and system integrity status")
    public DashboardSummary summary(@AuthenticationPrincipal AuthenticatedUser user) {
        var chain = auditService.verifyChain();

        return new DashboardSummary(
                documents.countOwnedBy(user.id()),
                documents.countSignedBy(user.id()),
                verifications.countByVerdict(VerificationVerdict.VALID),
                verifications.countByVerdict(VerificationVerdict.VALID_UNTRUSTED),
                verifications.countByVerdict(VerificationVerdict.INVALID),
                verifications.countTampering(),
                signingMaterial.trustAnchors().size(),
                chain.intact(),
                chain.explanation(),
                signingMaterial.description(),
                signingMaterial.developmentOnly(),
                auditService.recentActivity());
    }
}
