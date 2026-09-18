package com.docutrust.document.application;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.springframework.stereotype.Component;

import com.docutrust.common.config.DocuTrustProperties;
import com.docutrust.document.domain.UnsupportedDocumentException;

/**
 * Validates and normalises an uploaded file before it is stored.
 *
 * <p>Upload is the system's main untrusted input, so each check exists for a
 * specific reason rather than as ceremony.
 */
@Component
public class PdfUploadValidator {

    /** Every PDF begins with these bytes. */
    private static final byte[] PDF_MAGIC = "%PDF-".getBytes(StandardCharsets.US_ASCII);

    private static final int MAX_FILENAME_LENGTH = 200;

    private final DocuTrustProperties properties;

    public PdfUploadValidator(DocuTrustProperties properties) {
        this.properties = properties;
    }

    /**
     * Validates the upload and returns the document's page count.
     *
     * @throws UnsupportedDocumentException if the file is rejected
     */
    public int validate(byte[] content, String declaredContentType) {
        if (content == null || content.length == 0) {
            throw new UnsupportedDocumentException("The uploaded file is empty.");
        }

        // 1. Size. Checked again here because the container limit can be
        //    configured independently and this is the limit the domain owns.
        long maxBytes = properties.getUpload().maxSizeBytes();
        if (content.length > maxBytes) {
            throw new UnsupportedDocumentException(
                    "The file exceeds the maximum size of "
                            + properties.getUpload().getMaxSizeMb() + " MB.");
        }

        // 2. Magic bytes, not the declared Content-Type.
        //    The declared type is supplied by the client and can say anything;
        //    trusting it would let an attacker upload arbitrary content labelled
        //    as a PDF. The file's own first bytes are the only meaningful check.
        if (!startsWithPdfMagic(content)) {
            throw new UnsupportedDocumentException(
                    "The file is not a PDF. Only PDF documents can be uploaded.");
        }

        // 3. Structural parse. A file can start with %PDF- and still be
        //    unusable. Parsing now means signing does not fail later on a file
        //    that was never viable.
        try (PDDocument document = Loader.loadPDF(content)) {

            if (document.isEncrypted()) {
                throw new UnsupportedDocumentException(
                        "This PDF is encrypted. Remove document encryption before uploading, "
                                + "since an encrypted document cannot be signed.");
            }

            int pageCount = document.getNumberOfPages();
            if (pageCount < 1) {
                throw new UnsupportedDocumentException("The PDF contains no pages.");
            }
            return pageCount;

        } catch (UnsupportedDocumentException e) {
            throw e;
        } catch (IOException e) {
            // The parser's own message can expose internal offsets and class
            // names; it is logged upstream, not returned.
            throw new UnsupportedDocumentException(
                    "The PDF could not be read. It may be corrupted or incomplete.");
        }
    }

    /**
     * Reduces a client-supplied filename to something safe to store and echo.
     *
     * <p>Strips directory components and anything outside a conservative
     * character set. A filename is attacker-controlled text that ends up in
     * storage keys, HTTP headers and the user interface — {@code ../../etc/passwd}
     * and embedded newlines must not survive.
     */
    public String sanitiseFilename(String original) {
        if (original == null || original.isBlank()) {
            return "document.pdf";
        }

        // Strip any path, handling both separators regardless of platform.
        String name = original.replace('\\', '/');
        int lastSlash = name.lastIndexOf('/');
        if (lastSlash >= 0) {
            name = name.substring(lastSlash + 1);
        }

        name = name.replaceAll("[^A-Za-z0-9._ -]", "_").trim();

        while (name.startsWith(".")) {
            name = name.substring(1);
        }

        if (name.isBlank()) {
            name = "document.pdf";
        }
        if (name.length() > MAX_FILENAME_LENGTH) {
            name = name.substring(0, MAX_FILENAME_LENGTH);
        }
        if (!name.toLowerCase(Locale.ROOT).endsWith(".pdf")) {
            name = name + ".pdf";
        }
        return name;
    }

    private boolean startsWithPdfMagic(byte[] content) {
        if (content.length < PDF_MAGIC.length) {
            return false;
        }
        for (int i = 0; i < PDF_MAGIC.length; i++) {
            if (content[i] != PDF_MAGIC[i]) {
                return false;
            }
        }
        return true;
    }
}
