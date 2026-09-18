package com.docutrust.common.config;

import java.nio.file.Path;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import com.docutrust.audit.application.AuditChainHasher;
import com.docutrust.audit.application.AuditIntegrityService;
import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.devpki.DevPkiGenerator;
import com.docutrust.certificate.domain.RevocationService;
import com.docutrust.certificate.domain.TrustAnchorProvider;
import com.docutrust.certificate.infrastructure.DisabledRevocationService;
import com.docutrust.certificate.infrastructure.InMemoryTrustAnchorProvider;
import com.docutrust.common.crypto.DocumentHashService;
import com.docutrust.signature.domain.SigningProvider;
import com.docutrust.signature.infrastructure.Pkcs12SigningProvider;
import com.docutrust.storage.domain.DocumentStorage;
import com.docutrust.storage.infrastructure.FilesystemDocumentStorage;
import com.docutrust.timestamp.domain.TimestampService;
import com.docutrust.timestamp.infrastructure.NoOpTimestampService;
import com.docutrust.verification.application.TamperAnalysisService;
import com.docutrust.verification.application.VerificationService;

/**
 * Wires the cryptographic stack.
 *
 * <p>The central decision is where signing key material comes from. Exactly one
 * of two paths is taken, and which one is stated loudly at startup:
 *
 * <ol>
 *   <li>A configured PKCS#12 keystore, with trust anchors from a configured
 *       trust store.</li>
 *   <li>An ephemeral development PKI generated in memory — permitted only under
 *       the {@code local} profile.</li>
 * </ol>
 *
 * <p>The generated PKI is a <em>real</em> PKI: real RSA keys from a
 * {@link java.security.SecureRandom}, real X.509 certificates, real signatures.
 * Nothing about it is simulated. What it lacks is external trust — no relying
 * party has any reason to accept it — and it disappears on restart. Outside the
 * {@code local} profile, missing key material is a startup failure rather than
 * a silent fallback.
 */
@Configuration
public class CryptoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CryptoConfiguration.class);

    @Bean
    public SigningMaterial signingMaterial(DocuTrustProperties properties, Environment environment) {
        DocuTrustProperties.Signing signing = properties.getSigning();

        if (signing.hasKeystore()) {
            log.info("Loading signing key material from the configured PKCS#12 keystore");

            Pkcs12SigningProvider provider = Pkcs12SigningProvider.fromKeystore(
                    Path.of(signing.getPkcs12Path()),
                    signing.getPkcs12Password().toCharArray(),
                    signing.getPkcs12Alias().isBlank() ? null : signing.getPkcs12Alias());

            // Trust anchors come from the configured trust store. Falling back
            // to the signer's own chain would make the signer vouch for itself.
            List<java.security.cert.X509Certificate> anchors =
                    TrustStoreLoader.load(properties.getTrust());

            if (anchors.isEmpty()) {
                log.warn("No trust anchors are configured. Signatures will verify cryptographically "
                        + "but will be reported as VALID_UNTRUSTED, since no chain can reach a "
                        + "trusted root. Set DOCUTRUST_TRUSTSTORE_PATH to establish trust.");
            }

            return new SigningMaterial(provider, anchors,
                    "PKCS#12 keystore, " + anchors.size() + " configured trust anchor(s)", false);
        }

        if (!isLocalProfile(environment)) {
            throw new IllegalStateException("""
                    No signing keystore is configured and the active profile is not 'local'.
                    DocuTrust will not invent key material outside local development.
                    Set DOCUTRUST_PKCS12_PATH and DOCUTRUST_PKCS12_PASSWORD, or run with the
                    'local' profile to use a generated development PKI.""");
        }

        log.warn("""

                ============================================================
                 DEVELOPMENT PKI IN USE
                 No signing keystore configured; generating an ephemeral
                 three-tier PKI in memory (root CA -> issuing CA -> signer).
                 The keys are real, but they are regenerated on every restart
                 and carry no external trust whatsoever.
                 NEVER use this to sign anything of legal or commercial value.
                ============================================================""");

        DevPkiGenerator.DevPki devPki = new DevPkiGenerator().generateThreeTierPki();

        SigningProvider provider = new Pkcs12SigningProvider(
                devPki.signer().privateKey(), devPki.signerChain());

        return new SigningMaterial(provider,
                List.of(devPki.root().certificate()),
                "Ephemeral development PKI (regenerated at each startup)", true);
    }

    @Bean
    public SigningProvider signingProvider(SigningMaterial material) {
        return material.signingProvider();
    }

    @Bean
    public TrustAnchorProvider trustAnchorProvider(SigningMaterial material) {
        return new InMemoryTrustAnchorProvider(material.trustAnchors());
    }

    /**
     * Revocation checking.
     *
     * <p>Only the disabled implementation exists today, and it reports
     * {@code NOT_CHECKED} rather than implying a clean result. An OCSP/CRL
     * implementation plugs in here without touching any caller.
     */
    @Bean
    public RevocationService revocationService(DocuTrustProperties properties) {
        if (properties.getRevocation().isEnabled()) {
            log.warn("Revocation checking is enabled in configuration, but no OCSP/CRL "
                    + "implementation is present in this build. Revocation status will be "
                    + "reported as NOT_CHECKED rather than assumed good.");
        }
        return new DisabledRevocationService();
    }

    @Bean
    public CertificateValidationService certificateValidationService(
            TrustAnchorProvider trustAnchorProvider, RevocationService revocationService) {
        return new CertificateValidationService(trustAnchorProvider, revocationService);
    }

    /**
     * Timestamping.
     *
     * <p>Only the no-op implementation exists, so signatures produced here are
     * PAdES B-B rather than B-T. It obtains no token and reports that plainly.
     * An {@code Rfc3161TimestampService} plugs in here without touching any
     * caller.
     */
    @Bean
    public TimestampService timestampService(DocuTrustProperties properties) {
        if (properties.getTimestamp().isEnabled()) {
            log.warn("Timestamping is enabled in configuration, but no RFC 3161 client is "
                    + "present in this build. Timestamp status will be reported honestly "
                    + "rather than fabricated.");
        }
        return new NoOpTimestampService();
    }

    @Bean
    public TamperAnalysisService tamperAnalysisService() {
        return new TamperAnalysisService();
    }

    @Bean
    public VerificationService verificationService(
            DocumentHashService hashService,
            CertificateValidationService certificateValidationService,
            TamperAnalysisService tamperAnalysisService) {
        return new VerificationService(hashService, certificateValidationService, tamperAnalysisService);
    }

    @Bean
    public AuditChainHasher auditChainHasher(DocumentHashService hashService) {
        return new AuditChainHasher(hashService);
    }

    @Bean
    public AuditIntegrityService auditIntegrityService(AuditChainHasher hasher) {
        return new AuditIntegrityService(hasher);
    }

    @Bean
    public DocumentStorage documentStorage(DocuTrustProperties properties) {
        String backend = properties.getStorage().getBackend();

        if ("minio".equalsIgnoreCase(backend)) {
            // MinIO is the production path; see docs/ARCHITECTURE.md. It is not
            // wired in this build, and rather than silently writing documents
            // somewhere unexpected, this fails loudly.
            throw new IllegalStateException(
                    "MinIO storage backend is configured but not available in this build. "
                            + "Use the filesystem backend, or supply a MinioDocumentStorage bean.");
        }

        Path root = Path.of(properties.getStorage().getFilesystemRoot());
        log.info("Document storage: filesystem at {}", root.toAbsolutePath());
        return new FilesystemDocumentStorage(root);
    }

    private boolean isLocalProfile(Environment environment) {
        String[] active = environment.getActiveProfiles();
        if (active.length == 0) {
            return List.of(environment.getDefaultProfiles()).contains("local");
        }
        return List.of(active).contains("local");
    }
}
