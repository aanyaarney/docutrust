package com.docutrust.document.api;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.docutrust.audit.application.AuditService;
import com.docutrust.document.application.DocumentService;
import com.docutrust.document.domain.UnsupportedDocumentException;
import com.docutrust.document.infrastructure.DocumentEntity;
import com.docutrust.security.domain.AuthenticatedUser;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/** Document upload, listing, signing and download. */
@RestController
@RequestMapping("/api/v1/documents")
@Tag(name = "Documents")
public class DocumentController {

    private final DocumentService documentService;
    private final AuditService auditService;

    public DocumentController(DocumentService documentService, AuditService auditService) {
        this.documentService = documentService;
        this.auditService = auditService;
    }

    // ------------------------------------------------------------------ DTOs

    public record DocumentResponse(
            String id, String fileName, long sizeBytes, String sha256,
            Integer pageCount, String signatureState, Instant uploadedAt) {

        static DocumentResponse from(DocumentEntity entity) {
            return new DocumentResponse(entity.getId(), entity.getFileName(), entity.getSizeBytes(),
                    entity.getSha256(), entity.getPageCount(),
                    entity.getSignatureState().name(), entity.getUploadedAt());
        }
    }

    public record SignRequest(String reason, String location, String signerDisplayName,
                              Boolean visibleSignature) {
    }

    public record SignResponse(
            String documentId, String signerCommonName, String certificateSubject,
            String certificateIssuer, String certificateSerialNumber,
            String signatureAlgorithm, String digestAlgorithm, String signatureFormat,
            String providerName, Instant signingTime, long signedSizeBytes) {
    }

    public record VersionResponse(int versionNumber, String sha256, long sizeBytes,
                                  boolean signed, Instant createdAt) {
    }

    public record SignatureResponse(String signerCommonName, String certificateSubject,
                                    String certificateIssuer, String certificateSerial,
                                    String signatureAlgorithm, String digestAlgorithm,
                                    String signatureFormat, String reason, String location,
                                    Instant signedAt) {
    }

    // -------------------------------------------------------------- endpoints

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @Operation(summary = "Upload a PDF")
    public ResponseEntity<DocumentResponse> upload(@RequestParam("file") MultipartFile file,
                                                   @AuthenticationPrincipal AuthenticatedUser user) {
        byte[] content;
        try {
            content = file.getBytes();
        } catch (IOException e) {
            throw new UnsupportedDocumentException("The uploaded file could not be read.");
        }

        DocumentEntity document = documentService.upload(
                content, file.getOriginalFilename(), file.getContentType(), user);

        return ResponseEntity.status(201).body(DocumentResponse.from(document));
    }

    @GetMapping
    @Operation(summary = "List documents owned by the caller")
    public List<DocumentResponse> list(@AuthenticationPrincipal AuthenticatedUser user) {
        return documentService.list(user).stream().map(DocumentResponse::from).toList();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Fetch a document's metadata")
    public DocumentResponse get(@PathVariable String id,
                                @AuthenticationPrincipal AuthenticatedUser user) {
        return DocumentResponse.from(documentService.get(id, user));
    }

    @PostMapping("/{id}/sign")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @Operation(summary = "Apply a PAdES digital signature")
    public SignResponse sign(@PathVariable String id,
                             @RequestBody(required = false) SignRequest request,
                             @AuthenticationPrincipal AuthenticatedUser user) {

        SignRequest safe = request == null
                ? new SignRequest(null, null, null, false) : request;

        SignedDocument signed = documentService.sign(id, SignatureParameters.builder()
                .reason(safe.reason())
                .location(safe.location())
                .signerDisplayName(safe.signerDisplayName() != null
                        ? safe.signerDisplayName() : user.displayName())
                .visibleSignature(Boolean.TRUE.equals(safe.visibleSignature()))
                .build(), user);

        var certificate = com.docutrust.certificate.domain.CertificateDetails
                .from(signed.signerCertificate());

        return new SignResponse(id,
                safe.signerDisplayName() != null ? safe.signerDisplayName() : user.displayName(),
                certificate.subject(), certificate.issuer(), certificate.serialNumber(),
                signed.signatureAlgorithm(), signed.digestAlgorithm(), signed.signatureFormat(),
                signed.providerName(), signed.signingTime(), signed.sizeInBytes());
    }

    @GetMapping("/{id}/download")
    @Operation(summary = "Download a document, latest version by default")
    public ResponseEntity<Resource> download(@PathVariable String id,
                                             @RequestParam(required = false) Integer version,
                                             @AuthenticationPrincipal AuthenticatedUser user) {

        byte[] content = documentService.download(id, version, user);
        DocumentEntity document = documentService.get(id, user);

        // The filename is quoted and was sanitised on upload, so it cannot
        // inject additional header directives.
        String disposition = "attachment; filename=\"" + document.getFileName() + "\"";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, disposition)
                .contentType(MediaType.APPLICATION_PDF)
                .contentLength(content.length)
                .body(new ByteArrayResource(content));
    }

    @GetMapping("/{id}/versions")
    @Operation(summary = "List a document's versions")
    public List<VersionResponse> versions(@PathVariable String id,
                                          @AuthenticationPrincipal AuthenticatedUser user) {
        return documentService.versions(id, user).stream()
                .map(v -> new VersionResponse(v.getVersionNumber(), v.getSha256(),
                        v.getSizeBytes(), v.isSigned(), v.getCreatedAt()))
                .toList();
    }

    @GetMapping("/{id}/signatures")
    @Operation(summary = "List signatures recorded against a document")
    public List<SignatureResponse> signatures(@PathVariable String id,
                                              @AuthenticationPrincipal AuthenticatedUser user) {
        return documentService.signatures(id, user).stream()
                .map(s -> new SignatureResponse(s.getSignerCommonName(), s.getCertificateSubject(),
                        s.getCertificateIssuer(), s.getCertificateSerial(),
                        s.getSignatureAlgorithm(), s.getDigestAlgorithm(), s.getSignatureFormat(),
                        s.getReason(), s.getLocation(), s.getSignedAt()))
                .toList();
    }

    @GetMapping("/{id}/audit")
    @Operation(summary = "Audit history for a document")
    public List<com.docutrust.audit.domain.AuditRecord> audit(
            @PathVariable String id, @AuthenticationPrincipal AuthenticatedUser user) {
        documentService.get(id, user); // enforces ownership
        return auditService.historyFor(id);
    }
}
