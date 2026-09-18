package com.docutrust.timestamp;

import static org.assertj.core.api.Assertions.assertThat;

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
import com.docutrust.timestamp.domain.TimestampResult;
import com.docutrust.timestamp.domain.TimestampService;
import com.docutrust.timestamp.infrastructure.NoOpTimestampService;
import com.docutrust.verification.application.TamperAnalysisService;
import com.docutrust.verification.application.VerificationService;
import com.docutrust.verification.domain.TimestampStatus;
import com.docutrust.verification.domain.VerificationReport;

/**
 * Guards the rule that absence of a timestamp is never reported as a valid one.
 *
 * <p>This is the single easiest place for a system like this to quietly lie. The
 * signer's claimed signing time is right there in the signature and looks
 * authoritative, and showing it as a green "timestamp valid" would make every
 * demo look better. These tests exist to make that regression fail loudly.
 */
@DisplayName("Timestamp reporting honesty")
class TimestampHonestyTest {

    private static DevPkiGenerator.DevPki pki;

    private final PadesSigningService signingService = new PadesSigningService();

    @BeforeAll
    static void generatePki() {
        pki = new DevPkiGenerator().generateThreeTierPki();
    }

    private VerificationService verifier() {
        return new VerificationService(
                new Sha256DocumentHashService(),
                new CertificateValidationService(
                        InMemoryTrustAnchorProvider.of(pki.root().certificate()),
                        new DisabledRevocationService()),
                new TamperAnalysisService());
    }

    @Test
    @DisplayName("The no-op service obtains no token and says why")
    void noOpServiceReportsUnavailable() {
        TimestampService service = new NoOpTimestampService();

        TimestampResult result = service.timestamp("some signature value".getBytes());

        assertThat(service.isEnabled()).isFalse();
        assertThat(result.available()).isFalse();
        assertThat(result.token()).isNull();

        // It must explain the absence rather than return a bare false.
        assertThat(result.reason()).contains("Timestamp Authority");
    }

    @Test
    @DisplayName("A PAdES B-B signature reports NOT_AVAILABLE, never VALID")
    void baselineSignatureHasNoTimestamp() {
        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain()),
                SignatureParameters.builder().signerDisplayName("Demo Signer").build());

        VerificationReport report = verifier().verify(signed.pdfBytes(), "contract.pdf");
        var signature = report.signatures().get(0);

        assertThat(signature.timestamp()).isEqualTo(TimestampStatus.NOT_AVAILABLE);
        assertThat(signature.timestamp()).isNotEqualTo(TimestampStatus.VALID);

        // No authority and no attested time, because there is no token.
        assertThat(signature.timestampAuthority()).isNull();
        assertThat(signature.timestampAttestedTime()).isNull();
    }

    @Test
    @DisplayName("The signer's claimed time is never promoted to an attested time")
    void claimedTimeIsNotTreatedAsAttested() {
        SignedDocument signed = signingService.sign(
                TestPdfFactory.employmentContract("800,000"),
                new Pkcs12SigningProvider(pki.signer().privateKey(), pki.signerChain()),
                SignatureParameters.builder().signerDisplayName("Demo Signer").build());

        var signature = verifier().verify(signed.pdfBytes(), "contract.pdf").signatures().get(0);

        // The signature does carry a claimed signing time...
        assertThat(signature.claimedSigningTime()).isNotNull();

        // ...but it must not leak into the attested-time field, which is
        // reserved for what an independent authority asserted. Conflating the
        // two would present the signer's own claim as third-party evidence.
        assertThat(signature.timestampAttestedTime()).isNull();
        assertThat(signature.timestamp()).isEqualTo(TimestampStatus.NOT_AVAILABLE);
    }

    @Test
    @DisplayName("An unsigned document reports no timestamp state at all")
    void unsignedDocumentHasNoSignatureEntries() {
        VerificationReport report = verifier()
                .verify(TestPdfFactory.employmentContract("800,000"), "unsigned.pdf");

        assertThat(report.signatures()).isEmpty();
    }
}
