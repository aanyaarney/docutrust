package com.docutrust.signature;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.devpki.DevPkiGenerator;
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
import com.docutrust.verification.domain.SignatureStatus;
import com.docutrust.verification.domain.VerificationReport;
import com.docutrust.verification.domain.VerificationVerdict;

/**
 * The visible signature block.
 *
 * <p>The block is page content and proves nothing on its own. These tests
 * establish the two properties that actually matter: applying it must not
 * weaken or break the cryptographic signature, and because it lands inside the
 * signed byte range, editing it must break verification like any other content
 * change.
 */
@DisplayName("Visible signature appearance")
class VisibleSignatureTest {

    private static DevPkiGenerator.DevPki pki;

    private final PadesSigningService signingService = new PadesSigningService();

    @BeforeAll
    static void generatePki() {
        pki = new DevPkiGenerator().generateThreeTierPki();
    }

    private Pkcs12SigningProvider signer() {
        return new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain());
    }

    private VerificationService verifier() {
        return new VerificationService(
                new Sha256DocumentHashService(),
                new CertificateValidationService(
                        InMemoryTrustAnchorProvider.of(pki.root().certificate()),
                        new DisabledRevocationService()),
                new TamperAnalysisService());
    }

    private SignedDocument sign(boolean visible) {
        return signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                signer(),
                SignatureParameters.builder()
                        .signerDisplayName("Demo Signer")
                        .reason("I approve this employment agreement")
                        .location("Bengaluru, IN")
                        .visibleSignature(visible)
                        .build());
    }

    @Test
    @DisplayName("A visibly signed document still verifies as authentic")
    void visibleSignatureStillVerifies() {
        SignedDocument signed = sign(true);

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");

        assertThat(report.verdict()).isEqualTo(VerificationVerdict.VALID);

        var signature = report.signatures().get(0);
        assertThat(signature.integrity()).isEqualTo(IntegrityStatus.INTACT);
        assertThat(signature.signature()).isEqualTo(SignatureStatus.VALID);

        // The appearance is drawn before signing, so it sits inside the signed
        // byte range rather than being appended afterwards.
        assertThat(signature.coversEntireDocument()).isTrue();
    }

    @Test
    @DisplayName("The appearance adds content without adding a page")
    void appearanceDoesNotAlterPageCount() throws Exception {
        byte[] original = TestPdfFactory.employmentContract("800,000");
        SignedDocument signed = sign(true);

        try (PDDocument before = Loader.loadPDF(original);
             PDDocument after = Loader.loadPDF(signed.pdfBytes())) {

            assertThat(after.getNumberOfPages()).isEqualTo(before.getNumberOfPages());
            // The signature widget is a real annotation on the last page.
            assertThat(after.getSignatureDictionaries()).hasSize(1);
        }
    }

    @Test
    @DisplayName("A visible signature is larger on disk than an invisible one")
    void visibleSignatureCarriesTheAppearance() {
        SignedDocument invisible = sign(false);
        SignedDocument visible = sign(true);

        // The rendered block is embedded as an image, so the file must grow.
        // Equal sizes would mean the appearance was silently dropped.
        assertThat(visible.sizeInBytes()).isGreaterThan(invisible.sizeInBytes());
    }

    @Test
    @DisplayName("Editing content on a visibly signed document is still detected")
    void tamperingIsStillDetected() {
        SignedDocument signed = sign(true);

        byte[] tampered = TestPdfFactory.replacePreservingLength(
                signed.pdfBytes(), "800,000", "900,000");

        VerificationReport report = verifier().verify(tampered, "contract.pdf");

        // The visible block gives an attacker nothing: the cryptographic check
        // is unaffected by how convincing the page looks.
        assertThat(report.verdict()).isEqualTo(VerificationVerdict.TAMPERED);
        assertThat(report.signatures().get(0).integrity()).isEqualTo(IntegrityStatus.MODIFIED);
    }

    @Test
    @DisplayName("An invisible signature remains the default")
    void invisibleByDefault() {
        SignedDocument defaults = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                signer(),
                SignatureParameters.defaults());

        // Defaults must not draw anything: a signature is a cryptographic act,
        // and marking the page is a separate, explicit choice.
        assertThat(defaults.sizeInBytes()).isLessThan(sign(true).sizeInBytes());

        assertThat(verifier().verify(defaults.pdfBytes(), "contract.pdf").verdict())
                .isEqualTo(VerificationVerdict.VALID);
    }
}
