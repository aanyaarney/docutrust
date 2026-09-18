package com.docutrust.certificate.devpki;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates a development PKI: a root CA, an intermediate CA, and end-entity
 * signing certificates.
 *
 * <h2>DEVELOPMENT AND TESTING ONLY</h2>
 * Keys produced here live on the local filesystem and are generated on demand.
 * They carry no external trust and must never be used to sign anything of
 * legal or commercial consequence. Production signing keys belong inside an
 * HSM or cloud KMS boundary — see {@code docs/KMS_INTEGRATION.md}.
 *
 * <p>All cryptographic work is delegated to Bouncy Castle and the JDK.
 * DocuTrust implements no key generation, ASN.1 encoding or certificate
 * signing logic of its own (ADR-007).
 *
 * <p>The generator deliberately supports issuing <em>deliberately defective</em>
 * certificates (expired, not-yet-valid, untrusted). The attack simulation suite
 * needs genuinely bad certificates to prove that verification rejects them —
 * rejection cannot be demonstrated with mocks.
 */
public final class DevPkiGenerator {

    /**
     * RFC 9336 id-kp-documentSigning. Signals that the key is intended for
     * signing documents rather than TLS or code.
     */
    private static final KeyPurposeId DOCUMENT_SIGNING = KeyPurposeId.getInstance(
            new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.5.5.7.3.36"));

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * 2048-bit RSA. Adequate for the demonstration and fast enough that the
     * test suite regenerates a full three-tier PKI per run without dominating
     * runtime. Production deployments should prefer 3072-bit or ECDSA P-256.
     */
    private static final int DEFAULT_KEY_SIZE = 2048;

    /** Cryptographically secure randomness. Never {@code java.util.Random}. */
    private final SecureRandom secureRandom = new SecureRandom();

    private final int keySize;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public DevPkiGenerator() {
        this(DEFAULT_KEY_SIZE);
    }

    public DevPkiGenerator(int keySize) {
        this.keySize = keySize;
    }

    /**
     * Generates a complete, internally consistent three-tier PKI:
     * root CA → intermediate CA → signer.
     */
    public DevPki generateThreeTierPki() {
        Instant now = Instant.now();

        // Certificate authorities are backdated several years, as real ones are.
        // A CA must already have been valid when the certificates it issued were
        // issued; a root whose validity began yesterday cannot legitimately have
        // signed anything older than yesterday. Backdating also lets the attack
        // suite issue genuinely historical (expired) leaf certificates that
        // still chain correctly - which is precisely the real-world case of a
        // signature made while its certificate was live, verified after it
        // expired.
        KeyPair rootKeys = generateKeyPair();
        X509Certificate root = issue(CertificateSpec.builder()
                .subject("CN=DocuTrust Development Root CA, O=DocuTrust, OU=Development PKI, C=IN")
                .issuerCertificate(null)
                .issuerKey(rootKeys.getPrivate())
                .publicKey(rootKeys)
                .notBefore(now.minus(Duration.ofDays(3650)))
                .notAfter(now.plus(Duration.ofDays(3650)))
                .certificateAuthority(true)
                .build());

        KeyPair intermediateKeys = generateKeyPair();
        X509Certificate intermediate = issue(CertificateSpec.builder()
                .subject("CN=DocuTrust Development Issuing CA, O=DocuTrust, OU=Development PKI, C=IN")
                .issuerCertificate(root)
                .issuerKey(rootKeys.getPrivate())
                .publicKey(intermediateKeys)
                .notBefore(now.minus(Duration.ofDays(3600)))
                .notAfter(now.plus(Duration.ofDays(1825)))
                .certificateAuthority(true)
                .build());

        KeyPair signerKeys = generateKeyPair();
        X509Certificate signer = issue(CertificateSpec.builder()
                .subject("CN=Demo Signer, O=DocuTrust, OU=Demonstration, C=IN")
                .issuerCertificate(intermediate)
                .issuerKey(intermediateKeys.getPrivate())
                .publicKey(signerKeys)
                .notBefore(now.minus(Duration.ofDays(1)))
                .notAfter(now.plus(Duration.ofDays(730)))
                .certificateAuthority(false)
                .build());

        return new DevPki(
                new KeyedCertificate(root, rootKeys),
                new KeyedCertificate(intermediate, intermediateKeys),
                new KeyedCertificate(signer, signerKeys));
    }

    /**
     * Issues an end-entity signing certificate under an existing issuer, with
     * an explicit validity window.
     *
     * <p>Used by the attack suite to produce expired and not-yet-valid
     * certificates that are otherwise perfectly well-formed.
     */
    public KeyedCertificate issueSigner(String subject,
                                        KeyedCertificate issuer,
                                        Instant notBefore,
                                        Instant notAfter) {
        KeyPair keys = generateKeyPair();
        X509Certificate certificate = issue(CertificateSpec.builder()
                .subject(subject)
                .issuerCertificate(issuer.certificate())
                .issuerKey(issuer.keyPair().getPrivate())
                .publicKey(keys)
                .notBefore(notBefore)
                .notAfter(notAfter)
                .certificateAuthority(false)
                .build());
        return new KeyedCertificate(certificate, keys);
    }

    /**
     * Generates a self-signed end-entity certificate belonging to no chain.
     *
     * <p>Signatures made with this are cryptographically sound but chain to no
     * configured trust anchor, exercising the amber
     * "valid signature, trust not established" verdict.
     */
    public KeyedCertificate generateSelfSignedSigner(String subject) {
        Instant now = Instant.now();
        KeyPair keys = generateKeyPair();
        X509Certificate certificate = issue(CertificateSpec.builder()
                .subject(subject)
                .issuerCertificate(null)
                .issuerKey(keys.getPrivate())
                .publicKey(keys)
                .notBefore(now.minus(Duration.ofDays(1)))
                .notAfter(now.plus(Duration.ofDays(365)))
                .certificateAuthority(false)
                .build());
        return new KeyedCertificate(certificate, keys);
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", PROVIDER);
            generator.initialize(keySize, secureRandom);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new DevPkiException("Failed to generate an RSA key pair for the development PKI", e);
        }
    }

    private X509Certificate issue(CertificateSpec spec) {
        try {
            X500Name subject = new X500Name(spec.subject());

            // Take the issuer name from its DER encoding, not by re-parsing a
            // string form. Round-tripping through RFC 2253 text can change the
            // ASN.1 string types chosen for each attribute (PrintableString vs
            // UTF8String), producing a DN that is textually identical but
            // encodes to different bytes. PKIX path building compares encoded
            // names, so such a mismatch silently breaks chain construction.
            X500Name issuerName = spec.issuerCertificate() == null
                    ? subject // self-signed: the subject is its own issuer
                    : X500Name.getInstance(
                            spec.issuerCertificate().getSubjectX500Principal().getEncoded());

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuerName,
                    newSerialNumber(),
                    Date.from(spec.notBefore()),
                    Date.from(spec.notAfter()),
                    subject,
                    spec.publicKey().getPublic());

            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

            builder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(spec.certificateAuthority()));

            if (spec.certificateAuthority()) {
                builder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
            } else {
                // Document signing requires digitalSignature; nonRepudiation
                // (contentCommitment) is what makes the signature meaningful as
                // evidence of intent rather than mere authentication.
                builder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(DOCUMENT_SIGNING));
            }

            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensionUtils.createSubjectKeyIdentifier(spec.publicKey().getPublic()));

            // Authority key identifier binds this certificate to its issuer's
            // key, which is what lets a validator build the chain unambiguously.
            if (spec.issuerCertificate() != null) {
                builder.addExtension(Extension.authorityKeyIdentifier, false,
                        extensionUtils.createAuthorityKeyIdentifier(spec.issuerCertificate()));
            }

            ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                    .setProvider(PROVIDER)
                    .build(spec.issuerKey());

            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(holder);

        } catch (Exception e) {
            throw new DevPkiException("Failed to issue development certificate for subject: " + spec.subject(), e);
        }
    }

    /**
     * 160 bits of randomness, forced positive. Serial numbers must be unique
     * and unpredictable; a counter would leak issuance volume and collide
     * across independent generator instances.
     */
    private BigInteger newSerialNumber() {
        return new BigInteger(160, secureRandom).abs().add(BigInteger.ONE);
    }

    /** A certificate paired with the key material that owns it. */
    public record KeyedCertificate(X509Certificate certificate, KeyPair keyPair) {
        public PrivateKey privateKey() {
            return keyPair.getPrivate();
        }
    }

    /** A generated three-tier development PKI. */
    public record DevPki(KeyedCertificate root, KeyedCertificate intermediate, KeyedCertificate signer) {

        /** Signer chain ordered leaf-first, as required by CMS and PKIX. */
        public X509Certificate[] signerChain() {
            return new X509Certificate[]{
                    signer.certificate(), intermediate.certificate(), root.certificate()
            };
        }
    }
}
