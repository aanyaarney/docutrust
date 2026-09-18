package com.docutrust.signature;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.devpki.DevPkiGenerator;
import com.docutrust.certificate.domain.CertificateStatus;
import com.docutrust.certificate.domain.ChainStatus;
import com.docutrust.certificate.domain.RevocationStatus;
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
import com.docutrust.verification.domain.TimestampStatus;
import com.docutrust.verification.domain.VerificationReport;
import com.docutrust.verification.domain.VerificationVerdict;

/**
 * The core demonstration flow, exercised against real cryptography end to end.
 *
 * <p>Nothing here is mocked. A genuine three-tier PKI is generated, a genuine
 * PDF is signed with a genuine PAdES signature, and verification runs the same
 * code path the production API uses. The tampering test alters the signed file
 * the way an attacker would and asserts that the alteration is caught.
 */
@DisplayName("Sign, verify, tamper, detect")
class SignAndVerifyTest {

    private static DevPkiGenerator.DevPki pki;

    private final PadesSigningService signingService = new PadesSigningService();

    @BeforeAll
    static void generatePki() {
        // Generated once: a full three-tier PKI costs several RSA key pairs.
        pki = new DevPkiGenerator().generateThreeTierPki();
    }

    /** A verifier that trusts the development root CA. */
    private VerificationService verifierTrustingDevRoot() {
        CertificateValidationService certificateValidation = new CertificateValidationService(
                InMemoryTrustAnchorProvider.of(pki.root().certificate()),
                new DisabledRevocationService());

        return new VerificationService(
                new Sha256DocumentHashService(), certificateValidation, new TamperAnalysisService());
    }

    /** A verifier with no configured trust anchors. */
    private VerificationService verifierTrustingNobody() {
        CertificateValidationService certificateValidation = new CertificateValidationService(
                InMemoryTrustAnchorProvider.empty(), new DisabledRevocationService());

        return new VerificationService(
                new Sha256DocumentHashService(), certificateValidation, new TamperAnalysisService());
    }

    private Pkcs12SigningProvider devSigner() {
        return new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain());
    }

    private SignedDocument signContract(String salary) {
        byte[] original = TestPdfFactory.employmentContract(salary);
        return signingService.sign(original, devSigner(), SignatureParameters.builder()
                .reason("I approve this employment agreement")
                .location("Bengaluru, IN")
                .signerDisplayName("Demo Signer")
                .build());
    }

    // -----------------------------------------------------------------------

    @Test
    @DisplayName("A freshly signed document verifies as authentic")
    void signedDocumentIsAuthentic() {
        SignedDocument signed = signContract("800,000");

        VerificationReport report = verifierTrustingDevRoot()
                .verify(signed.pdfBytes(), "employment-contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID);
        assertThat(report.signatureCount()).isEqualTo(1);

        var signature = report.signatures().get(0);
        assertThat(signature.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(signature.signature()).isEqualTo(SignatureStatus.VALID);
        assertThat(signature.certificate().status()).isEqualTo(CertificateStatus.VALID);
        assertThat(signature.certificate().chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        assertThat(signature.tamperAnalysis().tampered()).isFalse();
        assertThat(signature.tamperAnalysis().modificationType()).isEqualTo(ModificationType.NONE);

        // The signature is a real PAdES signature, not a legacy PKCS#7 one.
        assertThat(signature.signatureFormat()).contains("ETSI.CAdES.detached");
        assertThat(signature.digestAlgorithm()).isEqualTo("SHA256");

        // The algorithm must read as a conventional JCA name. Bouncy Castle
        // resolves the SignerInfo OID to a complete name already, so a naive
        // "digest + with + encryption" concatenation yields the nonsensical
        // "SHA256withSHA256WITHRSA".
        assertThat(signature.signatureAlgorithm()).isEqualTo("SHA256withRSA");
    }

    @Test
    @DisplayName("No timestamp is configured, so timestamp status is NOT_AVAILABLE — never VALID")
    void timestampIsReportedHonestly() {
        SignedDocument signed = signContract("800,000");

        VerificationReport report = verifierTrustingDevRoot()
                .verify(signed.pdfBytes(), "employment-contract.pdf");

        assertThat(report.signatures().get(0).timestamp()).isEqualTo(TimestampStatus.NOT_AVAILABLE);
    }

    @Test
    @DisplayName("No revocation check was performed, so status is NOT_CHECKED — never GOOD")
    void revocationIsReportedHonestly() {
        SignedDocument signed = signContract("800,000");

        VerificationReport report = verifierTrustingDevRoot()
                .verify(signed.pdfBytes(), "employment-contract.pdf");

        assertThat(report.signatures().get(0).certificate().revocationStatus())
                .isEqualTo(RevocationStatus.NOT_CHECKED);
    }

    // -----------------------------------------------------------------------
    // The central demonstration: alter a signed document and detect it.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Altering the salary after signing is detected as tampering")
    void tamperingIsDetected() {
        SignedDocument signed = signContract("800,000");

        // Confirm the honest starting point before tampering.
        assertThat(verifierTrustingDevRoot().verify(signed.pdfBytes(), "contract.pdf").verdict())
                .isEqualTo(VerificationVerdict.VALID);

        // A same-length substitution: the file stays structurally valid and
        // every byte offset is preserved. Only signed content changed.
        byte[] tampered = TestPdfFactory.replacePreservingLength(
                signed.pdfBytes(), "800,000", "900,000");

        assertThat(tampered).hasSameSizeAs(signed.pdfBytes());
        assertThat(tampered).isNotEqualTo(signed.pdfBytes());

        VerificationReport report = verifierTrustingDevRoot().verify(tampered, "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.TAMPERED);

        var signature = report.signatures().get(0);
        assertThat(signature.integrity()).isEqualTo(IntegrityStatus.MODIFIED);
        assertThat(signature.signature()).isEqualTo(SignatureStatus.INVALID);
        assertThat(signature.tamperAnalysis().tampered()).isTrue();
        assertThat(signature.tamperAnalysis().modificationType())
                .isEqualTo(ModificationType.SIGNED_CONTENT_CHANGED);

        // The finding rests on a digest mismatch, so it is proof, not inference.
        assertThat(signature.tamperAnalysis().cryptographicallyProven()).isTrue();
        assertThat(report.hasProvenTampering()).isTrue();
    }

    @Test
    @DisplayName("A tampered document still has a VALID certificate — the document changed, not the certificate")
    void tamperingDoesNotInvalidateTheCertificate() {
        SignedDocument signed = signContract("800,000");
        byte[] tampered = TestPdfFactory.replacePreservingLength(
                signed.pdfBytes(), "800,000", "900,000");

        VerificationReport report = verifierTrustingDevRoot().verify(tampered, "contract.pdf");

        var certificate = report.signatures().get(0).certificate();

        // This is the distinction specification section 7 insists on: content
        // modification must never be reported as a certificate problem.
        assertThat(certificate.status()).isEqualTo(CertificateStatus.VALID);
        assertThat(certificate.chainStatus()).isEqualTo(ChainStatus.TRUSTED);
        assertThat(certificate.validPeriod()).isTrue();
        assertThat(certificate.details().subject()).contains("Demo Signer");
    }

    @Test
    @DisplayName("Flipping a single bit in the signed range is enough to break the signature")
    void singleBitFlipIsDetected() {
        SignedDocument signed = signContract("800,000");
        byte[] pdf = signed.pdfBytes();

        // Offset 200 sits well inside the first signed span, far from the
        // reserved signature hole.
        byte[] tampered = TestPdfFactory.flipByteAt(pdf, 200);

        VerificationReport report = verifierTrustingDevRoot().verify(tampered, "contract.pdf");

        assertThat(report.verdict()).isIn(VerificationVerdict.TAMPERED, VerificationVerdict.ERROR);
    }

    // -----------------------------------------------------------------------

    @Test
    @DisplayName("A valid signature with no trust anchor is amber, not green and not red")
    void untrustedSignerProducesAmberVerdict() {
        SignedDocument signed = signContract("800,000");

        VerificationReport report = verifierTrustingNobody()
                .verify(signed.pdfBytes(), "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID_UNTRUSTED);

        var signature = report.signatures().get(0);
        // The cryptography is sound; only the trust relationship is missing.
        assertThat(signature.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(signature.signature()).isEqualTo(SignatureStatus.VALID);
        assertThat(signature.certificate().chainStatus()).isNotEqualTo(ChainStatus.TRUSTED);
    }

    @Test
    @DisplayName("An unsigned PDF is reported as UNSIGNED, not as a failure")
    void unsignedDocumentIsReportedAsUnsigned() {
        byte[] unsigned = TestPdfFactory.employmentContract("800,000");

        VerificationReport report = verifierTrustingDevRoot().verify(unsigned, "unsigned.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.UNSIGNED);
        assertThat(report.signatures()).isEmpty();
        assertThat(report.documentSha256()).hasSize(64);
    }

    @Test
    @DisplayName("A file that is not a PDF yields ERROR, which is neither pass nor fail")
    void malformedInputYieldsError() {
        byte[] notAPdf = "This is plainly not a PDF file.".getBytes();

        VerificationReport report = verifierTrustingDevRoot().verify(notAPdf, "broken.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.ERROR);
    }

    @Test
    @DisplayName("Signing preserves the original document and produces a larger, valid PDF")
    void signingProducesAStandaloneDocument() {
        byte[] original = TestPdfFactory.employmentContract("800,000");
        SignedDocument signed = signingService.sign(original, devSigner(), SignatureParameters.defaults());

        // Incremental update: the signed file contains the original and appends to it.
        assertThat(signed.sizeInBytes()).isGreaterThan(original.length);
        assertThat(signed.signatureFormat()).isEqualTo("PAdES-B-B");
        assertThat(signed.signatureAlgorithm()).isEqualTo("SHA256withRSA");
        assertThat(signed.providerName()).isEqualTo("PKCS12");
    }
}
