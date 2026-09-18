package com.docutrust.document.application;

import java.io.ByteArrayInputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.docutrust.audit.application.AuditService;
import com.docutrust.audit.domain.AuditEventType;
import com.docutrust.certificate.domain.CertificateDetails;
import com.docutrust.common.crypto.DocumentHashService;
import com.docutrust.common.observability.DocuTrustMetrics;
import com.docutrust.document.domain.SignatureState;
import com.docutrust.document.infrastructure.DocumentEntity;
import com.docutrust.document.infrastructure.DocumentVersionEntity;
import com.docutrust.security.domain.AuthenticatedUser;
import com.docutrust.signature.application.PadesSigningService;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;
import com.docutrust.signature.domain.SigningProvider;
import com.docutrust.signature.infrastructure.SignatureRecordEntity;
import com.docutrust.storage.domain.DocumentStorage;

/**
 * Document upload, signing and retrieval.
 *
 * <p>Orchestrates validation, hashing, storage and signing. Database writes are
 * delegated to {@link DocumentPersistenceService} so that transactions stay
 * short and never span object-storage or cryptographic work.
 */
@Service
public class DocumentService {

    private static final Logger log = LoggerFactory.getLogger(DocumentService.class);
    private static final String PDF_CONTENT_TYPE = "application/pdf";

    private final PdfUploadValidator validator;
    private final DocumentHashService hashService;
    private final DocumentStorage storage;
    private final DocumentPersistenceService persistence;
    private final PadesSigningService signingService;
    private final SigningProvider signingProvider;
    private final AuditService auditService;
    private final DocuTrustMetrics metrics;

    public DocumentService(PdfUploadValidator validator,
                           DocumentHashService hashService,
                           DocumentStorage storage,
                           DocumentPersistenceService persistence,
                           PadesSigningService signingService,
                           SigningProvider signingProvider,
                           AuditService auditService,
                           DocuTrustMetrics metrics) {
        this.validator = validator;
        this.hashService = hashService;
        this.storage = storage;
        this.persistence = persistence;
        this.signingService = signingService;
        this.signingProvider = signingProvider;
        this.auditService = auditService;
        this.metrics = metrics;
    }

    /**
     * Validates, hashes and stores an uploaded PDF as version 0.
     */
    public DocumentEntity upload(byte[] content, String originalFilename,
                                 String declaredContentType, AuthenticatedUser user) {

        // --- outside any transaction: validation, hashing, storage I/O ---
        int pageCount = validator.validate(content, declaredContentType);
        String fileName = validator.sanitiseFilename(originalFilename);
        String sha256 = hashService.calculateSha256(content);

        String documentId = UUID.randomUUID().toString();
        String versionId = UUID.randomUUID().toString();
        String storageKey = storageKey(documentId, 0);

        storage.store(storageKey, new ByteArrayInputStream(content), PDF_CONTENT_TYPE, content.length);

        Instant now = Instant.now();

        DocumentEntity document = new DocumentEntity(
                documentId, fileName, user.id(), content.length, sha256,
                pageCount, PDF_CONTENT_TYPE, SignatureState.UNSIGNED, now);

        DocumentVersionEntity original = new DocumentVersionEntity(
                versionId, documentId, 0, storageKey, sha256, content.length, false, now);

        // --- short transaction: metadata only ---
        persistence.saveNewDocument(document, original);

        // Filenames can be confidential; the identifier is what gets logged.
        log.info("Document uploaded: id={} pages={} size={}B", documentId, pageCount, content.length);

        auditService.record(AuditEventType.DOCUMENT_UPLOADED, documentId, user.id(),
                "Document uploaded (" + pageCount + " pages, " + content.length + " bytes)");
        metrics.recordUpload();

        return document;
    }

    /**
     * Applies a PAdES signature to the document's latest version.
     *
     * <p>Signing the latest version rather than the original is what allows
     * multiple signatures: each signature is an incremental update layered on
     * the previous one, leaving earlier signatures intact.
     */
    public SignedDocument sign(String documentId, SignatureParameters parameters, AuthenticatedUser user) {

        DocumentEntity document = persistence.requireOwnedDocument(documentId, user.id());

        auditService.record(AuditEventType.SIGN_REQUESTED, documentId, user.id(),
                "Signature requested");

        DocumentVersionEntity latest = persistence.latestVersionOf(documentId)
                .orElseThrow(() -> new com.docutrust.document.domain.DocumentNotFoundException(documentId));

        // --- outside any transaction: storage read, then cryptography ---
        byte[] currentBytes = storage.retrieveAllBytes(latest.getStorageKey());

        long startedAt = System.nanoTime();
        SignedDocument signed;
        try {
            signed = signingService.sign(currentBytes, signingProvider, parameters);
        } catch (RuntimeException e) {
            metrics.recordSigningFailure();
            throw e;
        }
        Duration signingElapsed = Duration.ofNanos(System.nanoTime() - startedAt);

        byte[] signedBytes = signed.pdfBytes();

        int nextVersion = latest.getVersionNumber() + 1;
        String versionId = UUID.randomUUID().toString();
        String storageKey = storageKey(documentId, nextVersion);
        String signedSha256 = hashService.calculateSha256(signedBytes);

        storage.store(storageKey, new ByteArrayInputStream(signedBytes),
                PDF_CONTENT_TYPE, signedBytes.length);

        Instant now = Instant.now();
        CertificateDetails certificate = CertificateDetails.from(signed.signerCertificate());

        DocumentVersionEntity signedVersion = new DocumentVersionEntity(
                versionId, documentId, nextVersion, storageKey, signedSha256,
                signedBytes.length, true, now);

        SignatureRecordEntity signatureRecord = new SignatureRecordEntity(
                UUID.randomUUID().toString(), documentId, versionId, user.id(),
                parameters.signerDisplayName() != null ? parameters.signerDisplayName() : user.displayName(),
                certificate.subject(), certificate.issuer(), certificate.serialNumber(),
                signed.signatureAlgorithm(), signed.digestAlgorithm(), signed.signatureFormat(),
                signed.providerName(), parameters.reason(), parameters.location(),
                signed.signingTime());

        // --- short transaction: persist the new version and signature ---
        persistence.saveSignedVersion(documentId, signedVersion, signatureRecord);

        log.info("Document signed: id={} version={} algorithm={}",
                documentId, nextVersion, signed.signatureAlgorithm());

        auditService.record(AuditEventType.DOCUMENT_SIGNED, documentId, user.id(),
                "Signed with " + signed.signatureAlgorithm() + " (" + signed.signatureFormat()
                        + ") as version " + nextVersion);
        metrics.recordSigned(signingElapsed);

        return signed;
    }

    /** Bytes of a specific version, or the latest when {@code version} is null. */
    public byte[] download(String documentId, Integer version, AuthenticatedUser user) {
        persistence.requireOwnedDocument(documentId, user.id());

        DocumentVersionEntity target = version == null
                ? persistence.latestVersionOf(documentId)
                    .orElseThrow(() -> new com.docutrust.document.domain.DocumentNotFoundException(documentId))
                : persistence.versionsOf(documentId).stream()
                    .filter(v -> v.getVersionNumber() == version)
                    .findFirst()
                    .orElseThrow(() -> new com.docutrust.document.domain.DocumentNotFoundException(documentId));

        byte[] content = storage.retrieveAllBytes(target.getStorageKey());

        auditService.record(AuditEventType.DOCUMENT_DOWNLOADED, documentId, user.id(),
                "Downloaded version " + target.getVersionNumber());

        return content;
    }

    public List<DocumentEntity> list(AuthenticatedUser user) {
        return persistence.listOwnedBy(user.id());
    }

    public DocumentEntity get(String documentId, AuthenticatedUser user) {
        DocumentEntity document = persistence.requireOwnedDocument(documentId, user.id());
        auditService.record(AuditEventType.DOCUMENT_VIEWED, documentId, user.id(), "Document viewed");
        return document;
    }

    public List<DocumentVersionEntity> versions(String documentId, AuthenticatedUser user) {
        persistence.requireOwnedDocument(documentId, user.id());
        return persistence.versionsOf(documentId);
    }

    public List<SignatureRecordEntity> signatures(String documentId, AuthenticatedUser user) {
        persistence.requireOwnedDocument(documentId, user.id());
        return persistence.signaturesOf(documentId);
    }

    /** Storage keys are composed here, never taken from user input. */
    private String storageKey(String documentId, int version) {
        return "documents/" + documentId + "/v" + version + ".pdf";
    }
}
