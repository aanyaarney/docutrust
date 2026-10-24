package com.docutrust.testsupport;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.devpki.DevPkiGenerator;
import com.docutrust.certificate.infrastructure.DisabledRevocationService;
import com.docutrust.certificate.infrastructure.InMemoryTrustAnchorProvider;
import com.docutrust.common.crypto.Sha256DocumentHashService;
import com.docutrust.signature.application.PadesSigningService;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;
import com.docutrust.signature.infrastructure.Pkcs12SigningProvider;
import com.docutrust.verification.application.TamperAnalysisService;
import com.docutrust.verification.application.VerificationService;
import com.docutrust.verification.domain.VerificationReport;

/**
 * Measures signing and verification timings across document sizes.
 *
 * <p>Produces the figures used in the project report's results section. The
 * numbers are measured on the machine that runs it, not quoted from anywhere.
 *
 * <p>Each measurement discards warm-up iterations before recording, because the
 * JVM's just-in-time compiler leaves the first few runs unrepresentatively slow.
 * Reporting a cold first run as though it were steady-state performance is one
 * of the easiest ways to publish misleading benchmark figures.
 *
 * <pre>
 *   java -cp &lt;classpath&gt; com.docutrust.testsupport.PerformanceBenchmark
 * </pre>
 */
public final class PerformanceBenchmark {

    private static final int WARMUP_ITERATIONS = 3;
    private static final int MEASURED_ITERATIONS = 10;

    private PerformanceBenchmark() {
    }

    private record Measurement(
            int pages,
            int originalBytes,
            int signedBytes,
            double hashMillis,
            double signMillis,
            double verifyMillis) {
    }

    public static void main(String[] args) {
        System.out.println("Generating development PKI...");
        DevPkiGenerator.DevPki pki = new DevPkiGenerator().generateThreeTierPki();

        PadesSigningService signingService = new PadesSigningService();
        Sha256DocumentHashService hashService = new Sha256DocumentHashService();

        VerificationService verificationService = new VerificationService(
                hashService,
                new CertificateValidationService(
                        InMemoryTrustAnchorProvider.of(pki.root().certificate()),
                        new DisabledRevocationService()),
                new TamperAnalysisService());

        Pkcs12SigningProvider provider =
                new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain());

        SignatureParameters parameters = SignatureParameters.builder()
                .signerDisplayName("Benchmark Signer")
                .reason("Performance measurement")
                .build();

        int[] pageCounts = {1, 10, 50, 100, 250};
        List<Measurement> results = new ArrayList<>();

        for (int pages : pageCounts) {
            System.out.printf("Measuring %d page document...%n", pages);

            byte[] document = pages == 1
                    ? TestPdfFactory.employmentContract("800,000")
                    : TestPdfFactory.multiPageDocument(pages);

            // --- warm-up: let the JIT compile the hot paths ---
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                SignedDocument warm = signingService.sign(document, provider, parameters);
                verificationService.verify(warm.pdfBytes(), "warmup.pdf");
            }

            // --- hashing ---
            long hashNanos = 0;
            for (int i = 0; i < MEASURED_ITERATIONS; i++) {
                long start = System.nanoTime();
                hashService.calculateSha256(document);
                hashNanos += System.nanoTime() - start;
            }

            // --- signing ---
            long signNanos = 0;
            SignedDocument signed = null;
            for (int i = 0; i < MEASURED_ITERATIONS; i++) {
                long start = System.nanoTime();
                signed = signingService.sign(document, provider, parameters);
                signNanos += System.nanoTime() - start;
            }

            // --- verification ---
            byte[] signedBytes = signed.pdfBytes();
            long verifyNanos = 0;
            for (int i = 0; i < MEASURED_ITERATIONS; i++) {
                long start = System.nanoTime();
                VerificationReport report = verificationService.verify(signedBytes, "bench.pdf");
                verifyNanos += System.nanoTime() - start;

                if (report.verdict() != com.docutrust.verification.domain.VerificationVerdict.VALID) {
                    throw new IllegalStateException(
                            "Benchmark produced an invalid signature; figures would be meaningless");
                }
            }

            results.add(new Measurement(
                    pages,
                    document.length,
                    signedBytes.length,
                    toMillis(hashNanos),
                    toMillis(signNanos),
                    toMillis(verifyNanos)));
        }

        printTable(results);
        printTamperTiming(signingService, verificationService, provider, parameters);
        printEnvironment();
    }

    private static double toMillis(long totalNanos) {
        return Duration.ofNanos(totalNanos / MEASURED_ITERATIONS).toNanos() / 1_000_000.0;
    }

    private static void printTable(List<Measurement> results) {
        System.out.println();
        System.out.println("=".repeat(86));
        System.out.println("  PERFORMANCE RESULTS  (mean of " + MEASURED_ITERATIONS
                + " runs after " + WARMUP_ITERATIONS + " warm-up iterations)");
        System.out.println("=".repeat(86));
        System.out.printf("  %-7s %12s %12s %11s %11s %12s%n",
                "Pages", "Input (KB)", "Signed (KB)", "Hash (ms)", "Sign (ms)", "Verify (ms)");
        System.out.println("  " + "-".repeat(82));

        for (Measurement m : results) {
            System.out.printf("  %-7d %12.1f %12.1f %11.2f %11.2f %12.2f%n",
                    m.pages(),
                    m.originalBytes() / 1024.0,
                    m.signedBytes() / 1024.0,
                    m.hashMillis(),
                    m.signMillis(),
                    m.verifyMillis());
        }
        System.out.println("=".repeat(86));

        // Signature overhead is essentially constant: the CMS structure does not
        // grow with the document, only with the certificate chain.
        Measurement first = results.get(0);
        Measurement last = results.get(results.size() - 1);
        System.out.printf("%n  Signature overhead: %.1f KB on a %d-page file, %.1f KB on a %d-page file%n",
                (first.signedBytes() - first.originalBytes()) / 1024.0, first.pages(),
                (last.signedBytes() - last.originalBytes()) / 1024.0, last.pages());
    }

    /** Confirms that detecting a tampered file costs no more than accepting a valid one. */
    private static void printTamperTiming(PadesSigningService signingService,
                                          VerificationService verificationService,
                                          Pkcs12SigningProvider provider,
                                          SignatureParameters parameters) {
        byte[] document = TestPdfFactory.employmentContract("800,000");
        SignedDocument signed = signingService.sign(document, provider, parameters);
        byte[] tampered = TestPdfFactory.replacePreservingLength(
                signed.pdfBytes(), "800,000", "900,000");

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            verificationService.verify(tampered, "warmup.pdf");
        }

        long nanos = 0;
        for (int i = 0; i < MEASURED_ITERATIONS; i++) {
            long start = System.nanoTime();
            VerificationReport report = verificationService.verify(tampered, "tampered.pdf");
            nanos += System.nanoTime() - start;

            if (report.verdict() != com.docutrust.verification.domain.VerificationVerdict.TAMPERED) {
                throw new IllegalStateException("Tampering was not detected; figures would be meaningless");
            }
        }

        System.out.printf("  Tamper detection (1 page): %.2f ms%n", toMillis(nanos));
    }

    private static void printEnvironment() {
        System.out.println();
        System.out.println("  Environment");
        System.out.printf("    JVM        : %s %s%n",
                System.getProperty("java.vm.name"), System.getProperty("java.version"));
        System.out.printf("    OS         : %s %s%n",
                System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.printf("    Processors : %d%n", Runtime.getRuntime().availableProcessors());
        System.out.printf("    Max heap   : %d MB%n",
                Runtime.getRuntime().maxMemory() / (1024 * 1024));
        System.out.println();
        System.out.println("  Key: RSA 2048-bit, SHA-256, PAdES-B-B, 3-certificate chain");
    }
}
