package com.docutrust.testsupport;

import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.imageio.ImageIO;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;

import com.docutrust.certificate.devpki.DevPkiGenerator;
import com.docutrust.signature.application.PadesSigningService;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;
import com.docutrust.signature.infrastructure.Pkcs12SigningProvider;

/**
 * Produces a visibly signed sample PDF and a PNG preview of its last page.
 *
 * <p>A development tool. Automated tests can assert that a signature verifies
 * and that the file grew, but they cannot tell whether the appearance is
 * legible, correctly positioned, or clipped by the page edge. Those are
 * failures only a person looking at the output will catch.
 *
 * <pre>
 *   java -cp &lt;classpath&gt; com.docutrust.testsupport.VisibleSignaturePreview &lt;outputDir&gt;
 * </pre>
 */
public final class VisibleSignaturePreview {

    private VisibleSignaturePreview() {
    }

    public static void main(String[] args) throws Exception {
        Path outputDir = Path.of(args.length > 0 ? args[0] : "samples");
        Files.createDirectories(outputDir);

        DevPkiGenerator.DevPki pki = new DevPkiGenerator().generateThreeTierPki();

        SignedDocument signed = new PadesSigningService().sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain()),
                SignatureParameters.builder()
                        .signerDisplayName("Priya Raghavan")
                        .reason("I approve this employment agreement")
                        .location("Bengaluru, IN")
                        .visibleSignature(true)
                        .build());

        Path pdfPath = outputDir.resolve("visibly-signed-sample.pdf");
        Files.write(pdfPath, signed.pdfBytes());

        try (PDDocument document = Loader.loadPDF(signed.pdfBytes())) {
            PDFRenderer renderer = new PDFRenderer(document);
            // 110 DPI: enough to judge legibility without producing a huge file.
            BufferedImage page = renderer.renderImageWithDPI(document.getNumberOfPages() - 1, 110);

            File preview = outputDir.resolve("visibly-signed-preview.png").toFile();
            ImageIO.write(page, "png", preview);

            System.out.printf("PDF     : %s (%,d bytes)%n", pdfPath.toAbsolutePath(), signed.sizeInBytes());
            System.out.printf("Preview : %s (%dx%d)%n",
                    preview.getAbsolutePath(), page.getWidth(), page.getHeight());
        }
    }
}
