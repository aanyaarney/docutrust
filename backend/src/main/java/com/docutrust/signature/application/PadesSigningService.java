package com.docutrust.signature.application;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Objects;
import java.util.TimeZone;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.springframework.stereotype.Service;

import com.docutrust.signature.domain.SignRequest;
import com.docutrust.signature.domain.SignResult;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;
import com.docutrust.signature.domain.SigningFailedException;
import com.docutrust.signature.domain.SigningProvider;
import com.docutrust.signature.infrastructure.VisibleSignatureRenderer;

/**
 * Applies a PAdES Baseline-B digital signature to a PDF.
 *
 * <h2>How the signature protects the document</h2>
 * PDFBox writes an <em>incremental update</em> containing a signature
 * dictionary whose {@code /Contents} entry is a reserved block of zero bytes,
 * and whose {@code /ByteRange} names the two spans of the file that surround
 * that reserved hole. Those two spans are everything else in the file.
 *
 * <pre>
 *   [ ... PDF content ... ][ /Contents hole ][ ... PDF content ... ]
 *   |&lt;------- signed ------&gt;|   not signed   |&lt;------- signed ------&gt;|
 * </pre>
 *
 * The digest is computed over the concatenation of those two spans and signed.
 * Consequently <strong>any</strong> change to a single byte outside the hole —
 * text, metadata, page structure, an appended object — changes the digest and
 * causes verification to fail. This is what makes DocuTrust's tamper detection
 * cryptographic rather than a heuristic comparison.
 *
 * <h2>Multiple signatures</h2>
 * Because signing is an incremental update, the bytes of previously signed
 * revisions are never rewritten. A second signature appends to the file, and
 * the first signature's byte range still digests to the same value — so both
 * signatures remain valid. Rewriting the file instead of appending would
 * silently destroy every existing signature.
 */
@Service
public class PadesSigningService {

    /**
     * Bytes reserved for the CMS structure. A three-certificate chain with
     * 2048-bit RSA produces roughly 5 KB; 16 KB leaves headroom for longer
     * chains and future timestamp tokens without being wasteful.
     *
     * <p>Reserving too little causes signing to fail late, after the digest has
     * been computed, so the margin is deliberate.
     */
    private static final int RESERVED_SIGNATURE_BYTES = 16384;

    private static final String DIGEST_ALGORITHM = "SHA-256";

    /** Distance from the page edge for the visible block, in points. */
    private static final float VISIBLE_SIGNATURE_MARGIN = 28f;

    private final VisibleSignatureRenderer visibleSignatureRenderer = new VisibleSignatureRenderer();

    /**
     * Signs a PDF and returns a new, independently valid PDF.
     *
     * <p>The input array is never mutated.
     *
     * @param pdfBytes   the PDF to sign
     * @param provider   supplies the key operation and certificate chain
     * @param parameters reason, location, display name and appearance options
     * @return the signed PDF together with the facts describing the signature
     */
    public SignedDocument sign(byte[] pdfBytes, SigningProvider provider, SignatureParameters parameters) {
        Objects.requireNonNull(pdfBytes, "pdfBytes");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(parameters, "parameters");

        if (!provider.isAvailable()) {
            throw new SigningFailedException(
                    "Signing provider '" + provider.providerName() + "' is not available or not configured");
        }

        Instant signingTime = parameters.signingTime() != null ? parameters.signingTime() : Instant.now();

        try (PDDocument document = Loader.loadPDF(pdfBytes);
             SignatureOptions options = new SignatureOptions()) {

            if (document.isEncrypted()) {
                throw new SigningFailedException(
                        "Encrypted PDFs cannot be signed. Remove document encryption and retry.");
            }

            PDSignature signature = buildSignatureDictionary(parameters, signingTime);

            options.setPreferredSignatureSize(RESERVED_SIGNATURE_BYTES);

            if (parameters.visibleSignature()) {
                applyVisibleAppearance(document, options, parameters, signingTime);
            }

            document.addSignature(signature, options);

            ByteArrayOutputStream signedOutput = new ByteArrayOutputStream();

            // Prepares the incremental update and reserves the /Contents hole.
            // Everything except that hole becomes the signed byte range.
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(signedOutput);

            byte[] contentToSign = readFully(externalSigning.getContent());

            SignResult signResult = provider.sign(new SignRequest(
                    contentToSign,
                    DIGEST_ALGORITHM,
                    signingTime,
                    parameters.reason(),
                    parameters.location(),
                    parameters.signerDisplayName()));

            byte[] cms = signResult.cmsSignedData();

            if (cms.length > RESERVED_SIGNATURE_BYTES) {
                throw new SigningFailedException(
                        "The CMS signature (" + cms.length + " bytes) exceeds the reserved space ("
                                + RESERVED_SIGNATURE_BYTES + " bytes). Increase RESERVED_SIGNATURE_BYTES.");
            }

            // Writes the CMS structure into the reserved hole. The surrounding
            // bytes - those actually covered by the digest - are untouched.
            externalSigning.setSignature(cms);

            return new SignedDocument(
                    signedOutput.toByteArray(),
                    signResult.signerCertificate(),
                    signResult.signatureAlgorithm(),
                    signResult.digestAlgorithm(),
                    signingTime,
                    signResult.providerName(),
                    "PAdES-B-B");

        } catch (SigningFailedException e) {
            throw e;
        } catch (IOException e) {
            throw new SigningFailedException(
                    "Failed to sign the PDF. The file may be malformed or not a valid PDF.", e);
        }
    }

    /**
     * Draws the visible signature block on the last page, bottom-right.
     *
     * <h2>What this changes, and what it does not</h2>
     * The appearance is page content like any other. It adds nothing to the
     * cryptographic guarantee — a document with no visible block is exactly as
     * signed as one with a large ornate one, and a forged document can carry a
     * convincing block that means nothing.
     *
     * <p>What it <em>does</em> do is sit inside the signed byte range, so
     * editing the visible text breaks the signature. That is a consequence of
     * how PAdES works, not a property of the drawing.
     *
     * <p>Failure here is deliberately fatal rather than silently falling back
     * to an invisible signature: a caller who asked for a visible block and
     * received a document without one would reasonably conclude the signing did
     * not happen.
     */
    private void applyVisibleAppearance(PDDocument document,
                                        SignatureOptions options,
                                        SignatureParameters parameters,
                                        Instant signingTime) throws IOException {

        int pageCount = document.getNumberOfPages();
        int lastPage = pageCount; // PDVisibleSignDesigner pages are 1-based.

        PDRectangle mediaBox = document.getPage(pageCount - 1).getMediaBox();

        int blockWidth = visibleSignatureRenderer.widthPoints();
        int blockHeight = visibleSignatureRenderer.heightPoints();

        // Bottom-right, per the specification's default placement. The
        // designer's y axis runs downward from the top of the page.
        float x = mediaBox.getWidth() - blockWidth - VISIBLE_SIGNATURE_MARGIN;
        float y = mediaBox.getHeight() - blockHeight - VISIBLE_SIGNATURE_MARGIN;

        InputStream appearance = visibleSignatureRenderer.render(
                parameters.signerDisplayName(),
                signingTime,
                parameters.reason(),
                ZoneId.systemDefault());

        PDVisibleSignDesigner designer = new PDVisibleSignDesigner(document, appearance, lastPage);
        designer.xAxis(Math.max(0, x))
                .yAxis(Math.max(0, y))
                .width(blockWidth)
                .height(blockHeight);

        PDVisibleSigProperties visibleProperties = new PDVisibleSigProperties()
                .signerName(parameters.signerDisplayName() == null
                        ? "" : parameters.signerDisplayName())
                .signerLocation(parameters.location() == null ? "" : parameters.location())
                .signatureReason(parameters.reason() == null ? "" : parameters.reason())
                .preferredSize(0)
                .page(lastPage)
                .visualSignEnabled(true)
                .setPdVisibleSignature(designer);

        visibleProperties.buildSignature();
        options.setVisualSignature(visibleProperties.getVisibleSignature());
    }

    private PDSignature buildSignatureDictionary(SignatureParameters parameters, Instant signingTime) {
        PDSignature signature = new PDSignature();

        // ETSI.CAdES.detached is what makes this PAdES rather than a legacy
        // adbe.pkcs7.detached signature.
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);

        if (parameters.signerDisplayName() != null) {
            signature.setName(parameters.signerDisplayName());
        }
        if (parameters.reason() != null) {
            signature.setReason(parameters.reason());
        }
        if (parameters.location() != null) {
            signature.setLocation(parameters.location());
        }

        Calendar calendar = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        calendar.setTime(Date.from(signingTime));
        signature.setSignDate(calendar);

        return signature;
    }

    private static byte[] readFully(InputStream inputStream) throws IOException {
        try (InputStream in = inputStream) {
            return in.readAllBytes();
        }
    }
}
