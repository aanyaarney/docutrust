package com.docutrust.testsupport;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Writes the sample documents used for demonstrations.
 *
 * <p>Run with the test classpath:
 * {@code java -cp <classpath> com.docutrust.testsupport.SampleDocumentWriter <outputDir>}
 *
 * <p>Every name, figure and organisation in these documents is fictional
 * (specification section 59).
 */
public final class SampleDocumentWriter {

    private SampleDocumentWriter() {
    }

    public static void main(String[] args) throws Exception {
        Path outputDir = Path.of(args.length > 0 ? args[0] : "samples");
        Files.createDirectories(outputDir);

        write(outputDir.resolve("employment-contract-sample.pdf"),
                TestPdfFactory.employmentContract("800,000"));

        write(outputDir.resolve("offer-letter-sample.pdf"), TestPdfFactory.document(List.of(
                "OFFER OF EMPLOYMENT",
                "",
                "Northwind Textiles Pvt Ltd",
                "Bengaluru, Karnataka",
                "",
                "Dear Arjun Menon,",
                "",
                "We are pleased to offer you the position of Data Analyst.",
                "",
                "Position:         Data Analyst",
                "Reporting to:     Head of Analytics",
                "Start Date:       15 October 2026",
                "Annual Salary:    INR 650,000",
                "",
                "This offer is fictional and exists only to demonstrate",
                "digital signature verification.")));

        write(outputDir.resolve("nda-sample.pdf"), TestPdfFactory.document(List.of(
                "MUTUAL NON-DISCLOSURE AGREEMENT",
                "",
                "Between:  Northwind Textiles Pvt Ltd",
                "And:      Lakeside Analytics LLP",
                "",
                "Effective Date:   01 October 2026",
                "Term:             24 months",
                "",
                "Each party agrees to protect confidential information",
                "disclosed by the other party during the term.",
                "",
                "This agreement is fictional and has no legal effect.")));

        write(outputDir.resolve("multi-page-sample.pdf"), TestPdfFactory.multiPageDocument(3));

        System.out.println("Samples written to " + outputDir.toAbsolutePath());
    }

    private static void write(Path path, byte[] content) throws Exception {
        Files.write(path, content);
        System.out.printf("  %-40s %,7d bytes%n", path.getFileName(), content.length);
    }
}
