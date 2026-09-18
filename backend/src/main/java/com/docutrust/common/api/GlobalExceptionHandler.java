package com.docutrust.common.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import com.docutrust.certificate.domain.CertificateValidationException;
import com.docutrust.document.domain.DocumentNotFoundException;
import com.docutrust.document.domain.UnsupportedDocumentException;
import com.docutrust.signature.domain.SigningFailedException;
import com.docutrust.storage.domain.StorageException;

/**
 * Maps exceptions to the single {@link ApiError} shape.
 *
 * <p>Two rules govern everything here:
 *
 * <ol>
 *   <li>Messages returned to clients are written for this handler, not taken
 *       from exception text. An exception message may name a file path, a SQL
 *       fragment or a keystore location; none of that may reach a client.</li>
 *   <li>The full exception, including its stack trace, is logged with the
 *       correlation identifier. Detail is preserved where it is access
 *       controlled, and withheld where it is not.</li>
 * </ol>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(DocumentNotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(DocumentNotFoundException e) {
        log.info("Document not found [{}]", CorrelationIdFilter.current());
        return build(HttpStatus.NOT_FOUND, "DOCUMENT_NOT_FOUND",
                "The requested document does not exist, or you do not have access to it.");
    }

    @ExceptionHandler(UnsupportedDocumentException.class)
    public ResponseEntity<ApiError> handleUnsupported(UnsupportedDocumentException e) {
        log.info("Rejected unsupported document [{}]: {}",
                CorrelationIdFilter.current(), e.getMessage());
        // This message is authored to be safe and is genuinely useful to the
        // user, so it is passed through.
        return build(HttpStatus.BAD_REQUEST, "UNSUPPORTED_DOCUMENT", e.getMessage());
    }

    @ExceptionHandler(SigningFailedException.class)
    public ResponseEntity<ApiError> handleSigningFailure(SigningFailedException e) {
        log.error("Signing failed [{}]", CorrelationIdFilter.current(), e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "SIGNING_FAILED",
                "The document could not be signed. The signing service has recorded the details.");
    }

    @ExceptionHandler(CertificateValidationException.class)
    public ResponseEntity<ApiError> handleCertificateFailure(CertificateValidationException e) {
        log.warn("Certificate validation error [{}]", CorrelationIdFilter.current(), e);
        return build(HttpStatus.UNPROCESSABLE_ENTITY, "CERTIFICATE_VALIDATION_FAILED",
                "The certificate could not be validated.");
    }

    @ExceptionHandler(StorageException.class)
    public ResponseEntity<ApiError> handleStorageFailure(StorageException e) {
        // Storage messages can contain paths and bucket names.
        log.error("Storage failure [{}]", CorrelationIdFilter.current(), e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "STORAGE_ERROR",
                "Document storage is currently unavailable.");
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ApiError> handleTooLarge(MaxUploadSizeExceededException e) {
        return build(HttpStatus.PAYLOAD_TOO_LARGE, "FILE_TOO_LARGE",
                "The uploaded file exceeds the maximum permitted size.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException e) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .orElse("The request was not valid.");
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED", detail);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiError> handleAccessDenied(AccessDeniedException e) {
        log.warn("Access denied [{}]", CorrelationIdFilter.current());
        return build(HttpStatus.FORBIDDEN, "ACCESS_DENIED",
                "You do not have permission to perform this action.");
    }

    /**
     * Catch-all.
     *
     * <p>Returns a deliberately uninformative message. An unexpected exception
     * is exactly the case where internal detail is most likely to leak, so the
     * client gets a correlation identifier and nothing else.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleUnexpected(Exception e) {
        log.error("Unhandled exception [{}]", CorrelationIdFilter.current(), e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR",
                "An unexpected error occurred. Quote the correlation identifier when reporting it.");
    }

    private ResponseEntity<ApiError> build(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status)
                .body(ApiError.of(code, message, CorrelationIdFilter.current()));
    }
}
