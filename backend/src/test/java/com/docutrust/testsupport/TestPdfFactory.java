package com.docutrust.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

/**
 * Builds PDFs for tests.
 *
 * <p>Content streams are written <strong>uncompressed</strong> on purpose. That
 * lets a test locate a visible string in the raw file bytes and replace it with
 * another string of identical length, which simulates a realistic document
 * alteration while keeping every byte offset — and therefore the signature's
 * {@code /ByteRange} — structurally intact.
 *
 * <p>This matters for the honesty of the tamper test: the resulting file is
 * still a perfectly well-formed PDF that any reader will open. It fails
 * verification purely because the signed bytes changed, not because the file
 * was mangled into something unparseable.
 *
 * <p>All names and figures are fictional.
 */
public final class TestPdfFactory {

    private TestPdfFactory() {
    }

    /**
     * A one-page employment contract containing a salary figure.
     *
     * @param salary salary text, e.g. {@code "800,000"}
     */
    public static byte[] employmentContract(String salary) {
        return document(List.of(
                "EMPLOYMENT AGREEMENT",
                "",
                "This agreement is made between Northwind Textiles Pvt Ltd",
                "and the employee named below.",
                "",
                "Employee Name:    Priya Raghavan",
                "Position:         Senior Systems Engineer",
                "Start Date:       01 October 2026",
                "Annual Salary:    INR " + salary,
                "",
                "Both parties accept the terms set out in this agreement.",
                "",
                "This document is fictional and exists only for demonstration."
        ));
    }

    /** A minimal single-page PDF with arbitrary lines of text. */
    public static byte[] document(List<String> lines) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            document.addPage(page);

            PDType1Font font = new PDType1Font(Standard14Fonts.FontName.HELVETICA);

            // compress = false keeps the text visible in the raw file bytes.
            try (PDPageContentStream content = new PDPageContentStream(
                    document, page, PDPageContentStream.AppendMode.OVERWRITE, false, false)) {

                content.beginText();
                content.setFont(font, 12);
                content.setLeading(18f);
                content.newLineAtOffset(60, 760);
                for (String line : lines) {
                    content.showText(line);
                    content.newLine();
                }
                content.endText();
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();

        } catch (IOException e) {
            throw new UncheckedIOException("Failed to build test PDF", e);
        }
    }

    /** A multi-page PDF, for tests that append or inspect page structure. */
    public static byte[] multiPageDocument(int pages) {
        try (PDDocument document = new PDDocument()) {
            PDType1Font font = new PDType1Font(Standard14Fonts.FontName.HELVETICA);

            for (int i = 1; i <= pages; i++) {
                PDPage page = new PDPage(PDRectangle.A4);
                document.addPage(page);
                try (PDPageContentStream content = new PDPageContentStream(
                        document, page, PDPageContentStream.AppendMode.OVERWRITE, false, false)) {
                    content.beginText();
                    content.setFont(font, 14);
                    content.newLineAtOffset(72, 720);
                    content.showText("Page " + i + " of " + pages);
                    content.endText();
                }
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();

        } catch (IOException e) {
            throw new UncheckedIOException("Failed to build multi-page test PDF", e);
        }
    }

    /**
     * Replaces the first occurrence of {@code target} with {@code replacement}
     * directly in the file bytes.
     *
     * <p>Both strings must be the same length so that every byte offset in the
     * file is preserved. The file therefore remains structurally valid and the
     * signature's {@code /ByteRange} still points where it did — the only thing
     * that changed is content the signature covers.
     *
     * @throws IllegalArgumentException if lengths differ or the target is absent
     */
    public static byte[] replacePreservingLength(byte[] pdfBytes, String target, String replacement) {
        if (target.length() != replacement.length()) {
            throw new IllegalArgumentException(
                    "Replacement must preserve length so byte offsets stay valid: '"
                            + target + "' (" + target.length() + ") vs '"
                            + replacement + "' (" + replacement.length() + ")");
        }

        byte[] targetBytes = target.getBytes(StandardCharsets.ISO_8859_1);
        byte[] replacementBytes = replacement.getBytes(StandardCharsets.ISO_8859_1);

        int index = indexOf(pdfBytes, targetBytes);
        if (index < 0) {
            throw new IllegalArgumentException(
                    "Target string '" + target + "' not found in the PDF bytes. "
                            + "The content stream may be compressed.");
        }

        byte[] modified = pdfBytes.clone();
        System.arraycopy(replacementBytes, 0, modified, index, replacementBytes.length);
        return modified;
    }

    /** Flips a single bit at {@code offset}, the smallest possible alteration. */
    public static byte[] flipByteAt(byte[] data, int offset) {
        byte[] modified = data.clone();
        modified[offset] = (byte) (modified[offset] ^ 0x01);
        return modified;
    }

    /** Index of {@code needle} in {@code haystack}, or -1. */
    public static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
