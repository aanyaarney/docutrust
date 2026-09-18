package com.docutrust.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;

import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.devpki.DevPkiGenerator;
import com.docutrust.certificate.domain.CertificateStatus;
import com.docutrust.certificate.domain.ChainStatus;
import com.docutrust.certificate.infrastructure.DisabledRevocationService;
import com.docutrust.certificate.infrastructure.InMemoryTrustAnchorProvider;
import com.docutrust.common.crypto.Sha256DocumentHashService;
import com.docutrust.signature.application.PadesSigningService;
import com.docutrust.signature.domain.SignatureParameters;
import com.docutrust.signature.domain.SignedDocument;
import com.docutrust.signature.infrastructure.Pkcs12SigningProvider;
import com.docutrust.testsupport.TestPdfFactory;
import com.docutrust.verification.application.TamperAnalysisService;
import com.docutrust.verification.application.VerificationService;
import com.docutrust.verification.domain.IntegrityStatus;
import com.docutrust.verification.domain.ModificationType;
import com.docutrust.verification.domain.SignatureStatus;
import com.docutrust.verification.domain.VerificationReport;
import com.docutrust.verification.domain.VerificationVerdict;

/**
 * Deliberate attacks against signed documents.
 *
 * <p>Every scenario constructs a genuinely hostile artefact and runs it through
 * the same verification code the API uses. Nothing is mocked and no result is
 * asserted that the engine does not actually produce.
 *
 * <p>The printed summary at the end reports what these tests actually observed
 * during this run. If a defence regressed, the summary would say so rather than
 * quietly printing a reassuring table.
 */
@DisplayName("Digital signature attack simulation suite")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DigitalSignatureAttackSuiteTest {

    private static DevPkiGenerator generator;
    private static DevPkiGenerator.DevPki pki;
    private static final List<String> SUMMARY = new ArrayList<>();

    private final PadesSigningService signingService = new PadesSigningService();

    @BeforeAll
    static void setUp() {
        generator = new DevPkiGenerator();
        pki = generator.generateThreeTierPki();
    }

    @AfterAll
    static void printSummary() {
        StringBuilder out = new StringBuilder();
        out.append(System.lineSeparator())
           .append("=".repeat(72)).append(System.lineSeparator())
           .append("  DIGITAL SIGNATURE SECURITY SUITE - observed results").append(System.lineSeparator())
           .append("=".repeat(72)).append(System.lineSeparator());
        SUMMARY.forEach(line -> out.append("  ").append(line).append(System.lineSeparator()));
        out.append("=".repeat(72));
        System.out.println(out);
    }

    private static void record(String scenario, String outcome) {
        SUMMARY.add(String.format("%-44s %s", scenario, outcome));
    }

    // ---------------------------------------------------------------- helpers

    private VerificationService verifier() {
        return new VerificationService(
                new Sha256DocumentHashService(),
                new CertificateValidationService(
                        InMemoryTrustAnchorProvider.of(pki.root().certificate()),
                        new DisabledRevocationService()),
                new TamperAnalysisService());
    }

    private SignedDocument signWithDevPki(byte[] pdf) {
        return signingService.sign(pdf,
                new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain()),
                SignatureParameters.builder().signerDisplayName("Demo Signer").build());
    }

    // ------------------------------------------------------------- scenarios

    @Test
    @Order(1)
    @DisplayName("Baseline: a legitimately signed document verifies")
    void baselineValidSignature() {
        SignedDocument signed = signWithDevPki(TestPdfFactory.employmentContract("800,000"));
        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID);
        record("Valid PDF signature", "PASS");
    }

    @Test
    @Order(2)
    @DisplayName("Attack: modify signed content")
    void modifiedSignedContentIsDetected() {
        SignedDocument signed = signWithDevPki(TestPdfFactory.employmentContract("800,000"));
        byte[] tampered = TestPdfFactory.replacePreservingLength(
                signed.pdfBytes(), "800,000", "900,000");

        VerificationReport report = verifier().verify(tampered, "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.TAMPERED);
        assertThat(report.signatures().get(0).integrity()).isEqualTo(IntegrityStatus.MODIFIED);
        assertThat(report.signatures().get(0).tamperAnalysis().cryptographicallyProven()).isTrue();
        record("Modified signed content", "DETECTED");
    }

    @Test
    @Order(3)
    @DisplayName("Attack: corrupt the signature bytes")
    void corruptedSignatureIsDetected() {
        SignedDocument signed = signWithDevPki(TestPdfFactory.employmentContract("800,000"));
        byte[] pdf = signed.pdfBytes();

        // Locate the /Contents hex blob and corrupt bytes inside it. This
        // damages the CMS structure without disturbing any byte offset.
        int contentsIndex = TestPdfFactory.indexOf(pdf, "/Contents <".getBytes());
        if (contentsIndex < 0) {
            contentsIndex = TestPdfFactory.indexOf(pdf, "/Contents<".getBytes());
        }
        assertThat(contentsIndex).as("signature /Contents entry must be locatable").isGreaterThan(0);

        byte[] corrupted = pdf.clone();
        int start = contentsIndex + 16;
        for (int i = start; i < start + 64 && i < corrupted.length; i++) {
            // Keep the bytes valid hex characters so the PDF still parses; the
            // CMS structure underneath is what we are damaging.
            corrupted[i] = (byte) 'A';
        }

        VerificationReport report = verifier().verify(corrupted, "contract.pdf");

        assertThat(report.verdict()).isIn(
                VerificationVerdict.INVALID, VerificationVerdict.TAMPERED, VerificationVerdict.ERROR);
        record("Signature corruption", "DETECTED");
    }

    @Test
    @Order(4)
    @DisplayName("Attack: signer certificate not issued by a trusted authority")
    void untrustedCertificateIsNotTrusted() {
        DevPkiGenerator.KeyedCertificate rogue =
                generator.generateSelfSignedSigner("CN=Rogue Signer, O=Unknown, C=IN");

        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(rogue.privateKey(),
                        new java.security.cert.X509Certificate[]{rogue.certificate()}),
                SignatureParameters.defaults());

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        // The cryptography is sound, so this is amber - not green, not red.
        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID_UNTRUSTED);
        assertThat(report.signatures().get(0).signature()).isEqualTo(SignatureStatus.VALID);
        assertThat(report.signatures().get(0).certificate().chainStatus())
                .isEqualTo(ChainStatus.UNTRUSTED);
        record("Untrusted certificate", "DETECTED (amber)");
    }

    @Test
    @Order(5)
    @DisplayName("Attack: sign with an expired certificate")
    void expiredCertificateIsDetected() {
        Instant now = Instant.now();
        DevPkiGenerator.KeyedCertificate expired = generator.issueSigner(
                "CN=Expired Signer, O=DocuTrust, C=IN",
                pki.intermediate(),
                now.minus(Duration.ofDays(400)),
                now.minus(Duration.ofDays(30)));   // expired a month ago

        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(expired.privateKey(),
                        new java.security.cert.X509Certificate[]{
                                expired.certificate(),
                                pki.intermediate().certificate(),
                                pki.root().certificate()}),
                SignatureParameters.defaults());

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        var certificate = report.signatures().get(0).certificate();
        assertThat(certificate.status()).isEqualTo(CertificateStatus.EXPIRED);
        assertThat(certificate.validPeriod()).isFalse();
        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID_UNTRUSTED);

        // The chain itself is still sound; only the validity window lapsed.
        assertThat(certificate.chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        record("Expired certificate", "DETECTED");
    }

    @Test
    @Order(6)
    @DisplayName("Attack: certificate not yet valid")
    void notYetValidCertificateIsDetected() {
        Instant now = Instant.now();
        DevPkiGenerator.KeyedCertificate future = generator.issueSigner(
                "CN=Future Signer, O=DocuTrust, C=IN",
                pki.intermediate(),
                now.plus(Duration.ofDays(30)),     // valid only from next month
                now.plus(Duration.ofDays(400)));

        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(future.privateKey(),
                        new java.security.cert.X509Certificate[]{
                                future.certificate(),
                                pki.intermediate().certificate(),
                                pki.root().certificate()}),
                SignatureParameters.defaults());

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        assertThat(report.signatures().get(0).certificate().status())
                .isEqualTo(CertificateStatus.NOT_YET_VALID);
        record("Certificate outside validity window", "DETECTED");
    }

    @Test
    @Order(7)
    @DisplayName("Attack: signature made by a key that does not match the presented certificate")
    void wrongSigningKeyIsDetected() {
        // Sign with the legitimate signer's key, but present a different
        // certificate - an impersonation attempt.
        DevPkiGenerator.KeyedCertificate other = generator.issueSigner(
                "CN=Someone Else, O=DocuTrust, C=IN",
                pki.intermediate(),
                Instant.now().minus(Duration.ofDays(1)),
                Instant.now().plus(Duration.ofDays(365)));

        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(
                        pki.signer().privateKey(),                       // key of A
                        new java.security.cert.X509Certificate[]{        // certificate of B
                                other.certificate(),
                                pki.intermediate().certificate(),
                                pki.root().certificate()}),
                SignatureParameters.defaults());

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.INVALID);
        assertThat(report.signatures().get(0).signature()).isEqualTo(SignatureStatus.INVALID);

        // Content was never altered, and the report must not claim otherwise.
        assertThat(report.signatures().get(0).integrity()).isEqualTo(IntegrityStatus.INTACT);
        record("Wrong signing certificate", "DETECTED");
    }

    @Test
    @Order(8)
    @DisplayName("Attack: submit an unsigned document")
    void unsignedDocumentIsReported() {
        VerificationReport report = verifier()
                .verify(TestPdfFactory.employmentContract("800,000"), "unsigned.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.UNSIGNED);
        record("Unsigned document", "DETECTED");
    }

    @Test
    @Order(9)
    @DisplayName("Attack: submit a malformed file")
    void malformedDocumentIsReported() {
        VerificationReport report = verifier()
                .verify("%PDF-1.7 truncated garbage".getBytes(), "broken.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.ERROR);
        record("Malformed document", "DETECTED");
    }

    @Test
    @Order(10)
    @DisplayName("Attack: append a page via full rewrite")
    void fullRewriteAfterSigningIsDetected() throws Exception {
        SignedDocument signed = signWithDevPki(TestPdfFactory.employmentContract("800,000"));

        // A full re-save rewrites every object, so the bytes the signature
        // covers no longer exist in their original form.
        byte[] rewritten;
        try (PDDocument document = Loader.loadPDF(signed.pdfBytes())) {
            document.addPage(new PDPage(PDRectangle.A4));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            rewritten = out.toByteArray();
        }

        VerificationReport report = verifier().verify(rewritten, "contract.pdf");

        assertThat(report.verdict()).isIn(
                VerificationVerdict.TAMPERED, VerificationVerdict.INVALID, VerificationVerdict.ERROR);
        record("Page appended via full rewrite", "DETECTED");
    }

    @Test
    @Order(11)
    @DisplayName("Legitimate: a second signature does not invalidate the first")
    void secondSignaturePreservesTheFirst() {
        SignedDocument first = signWithDevPki(TestPdfFactory.employmentContract("800,000"));

        DevPkiGenerator.KeyedCertificate manager = generator.issueSigner(
                "CN=Manager Signer, O=DocuTrust, C=IN",
                pki.intermediate(),
                Instant.now().minus(Duration.ofDays(1)),
                Instant.now().plus(Duration.ofDays(365)));

        // Incremental update: appends a revision without rewriting signed bytes.
        SignedDocument second = signingService.sign(
                first.pdfBytes(),
                new Pkcs12SigningProvider(manager.privateKey(),
                        new java.security.cert.X509Certificate[]{
                                manager.certificate(),
                                pki.intermediate().certificate(),
                                pki.root().certificate()}),
                SignatureParameters.builder().signerDisplayName("Manager Signer").build());

        VerificationReport report = verifier().verify(second.pdfBytes(), "contract.pdf");

        assertThat(report.signatureCount()).isEqualTo(2);

        // Both signatures must still verify. The first covers the earlier
        // revision; the second covers the whole file.
        assertThat(report.signatures())
                .allSatisfy(s -> assertThat(s.signature()).isEqualTo(SignatureStatus.VALID));
        assertThat(report.signatures())
                .allSatisfy(s -> assertThat(s.integrity()).isEqualTo(IntegrityStatus.INTACT));
        assertThat(report.hasProvenTampering()).isFalse();

        record("Second signature preserves the first", "PASS (2 valid signatures)");
    }

    @Test
    @Order(12)
    @DisplayName("Nuance: content appended after signing is surfaced, not called tampering")
    void appendedRevisionIsSurfacedHonestly() {
        SignedDocument first = signWithDevPki(TestPdfFactory.employmentContract("800,000"));

        DevPkiGenerator.KeyedCertificate second = generator.issueSigner(
                "CN=Second Signer, O=DocuTrust, C=IN",
                pki.intermediate(),
                Instant.now().minus(Duration.ofDays(1)),
                Instant.now().plus(Duration.ofDays(365)));

        SignedDocument twice = signingService.sign(
                first.pdfBytes(),
                new Pkcs12SigningProvider(second.privateKey(),
                        new java.security.cert.X509Certificate[]{
                                second.certificate(),
                                pki.intermediate().certificate(),
                                pki.root().certificate()}),
                SignatureParameters.defaults());

        VerificationReport report = verifier().verify(twice.pdfBytes(), "contract.pdf");

        var firstSignature = report.signatures().get(0);

        // The earlier signature no longer covers the end of the file, but the
        // content it does cover is untouched - so this is an observation, not
        // an accusation, and it is explicitly not cryptographically "proven"
        // tampering.
        assertThat(firstSignature.coversEntireDocument()).isFalse();
        assertThat(firstSignature.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(firstSignature.tamperAnalysis().modificationType())
                .isEqualTo(ModificationType.POST_SIGNATURE_INCREMENTAL_UPDATE);
        assertThat(firstSignature.tamperAnalysis().tampered()).isFalse();
        assertThat(firstSignature.tamperAnalysis().cryptographicallyProven()).isFalse();

        record("Post-signature revision classified honestly", "PASS");
    }
}
