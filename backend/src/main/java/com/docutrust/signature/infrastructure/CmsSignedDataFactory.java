package com.docutrust.signature.infrastructure;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.docutrust.signature.domain.SigningFailedException;

/**
 * Builds detached CMS SignedData structures conforming to PAdES Baseline-B.
 *
 * <p>Shared by every {@code SigningProvider}: providers differ in <em>how</em>
 * the raw signature is produced (local key, HSM, KMS), not in the CMS structure
 * they emit. Keeping assembly here means a future KMS provider cannot
 * accidentally emit a structurally different — and possibly non-conformant —
 * signature.
 *
 * <p>All ASN.1 encoding and CMS construction is performed by Bouncy Castle.
 * DocuTrust writes none of it (ADR-007).
 *
 * <h2>Required signed attributes</h2>
 * <ul>
 *   <li><b>content-type</b> and <b>message-digest</b> — added automatically by
 *       Bouncy Castle's {@link DefaultSignedAttributeTableGenerator}.</li>
 *   <li><b>signing-certificate-v2</b> (RFC 5035) — added explicitly here.
 *       PAdES <em>requires</em> it. It carries a hash of the signer certificate
 *       inside the signed attributes, binding the signature to one specific
 *       certificate. Without it, an attacker could substitute a different
 *       certificate carrying the same public key and change the apparent
 *       identity of the signer.</li>
 *   <li><b>signing-time</b> — the signer's own claim about when it signed.
 *       Asserted, never proven. Only an RFC 3161 timestamp proves time.</li>
 * </ul>
 */
public class CmsSignedDataFactory {

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Builds a detached CMS SignedData structure over {@code content}.
     *
     * @param content        exact bytes covered by the signature (the PDF signed byte range)
     * @param privateKey     key performing the signature
     * @param chain          signer chain, leaf-first; embedded so verifiers can build a path
     * @param signatureAlgorithm JCA signature algorithm name, e.g. {@code SHA256withRSA}
     * @param signingTime    time asserted in the signed attributes
     * @return DER-encoded CMS SignedData
     */
    public byte[] buildDetachedSignature(byte[] content,
                                         PrivateKey privateKey,
                                         X509Certificate[] chain,
                                         String signatureAlgorithm,
                                         Instant signingTime) {
        if (chain == null || chain.length == 0) {
            throw new SigningFailedException("Cannot build a CMS signature without a certificate chain");
        }

        X509Certificate signerCertificate = chain[0];

        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            ContentSigner contentSigner = new JcaContentSignerBuilderCompat(signatureAlgorithm).build(privateKey);

            JcaSignerInfoGeneratorBuilder signerInfoBuilder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build());

            signerInfoBuilder.setSignedAttributeGenerator(
                    new DefaultSignedAttributeTableGenerator(
                            buildSignedAttributes(signerCertificate, signingTime)));

            generator.addSignerInfoGenerator(
                    signerInfoBuilder.build(contentSigner, new JcaX509CertificateHolder(signerCertificate)));

            // Embed the full chain so a verifier can attempt path construction
            // even when it holds only the trust anchor.
            generator.addCertificates(new JcaCertStore(Arrays.asList(chain)));

            CMSTypedData typedData = new CMSProcessableByteArray(content);

            // `false` => detached. The PDF holds the content; the signature
            // structure must not duplicate it inside /Contents.
            CMSSignedData signedData = generator.generate(typedData, false);

            return signedData.getEncoded();

        } catch (SigningFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new SigningFailedException(
                    "Failed to build CMS SignedData structure using " + signatureAlgorithm, e);
        }
    }

    /**
     * Assembles the PAdES-required signed attribute table.
     *
     * <p>These attributes are themselves covered by the signature, so tampering
     * with any of them invalidates it.
     */
    private AttributeTable buildSignedAttributes(X509Certificate signerCertificate, Instant signingTime) {
        try {
            Hashtable<org.bouncycastle.asn1.ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();

            // --- signing-certificate-v2 (RFC 5035), mandatory for PAdES ---
            byte[] certificateHash = MessageDigest.getInstance("SHA-256")
                    .digest(signerCertificate.getEncoded());

            // Single-argument ESSCertIDv2 defaults to SHA-256, matching the digest above.
            ESSCertIDv2 essCertId = new ESSCertIDv2(certificateHash);
            SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertId);

            attributes.put(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                    new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                            new DERSet(signingCertificateV2)));

            // --- signing-time: the signer's claim, not proof ---
            ASN1EncodableVector timeVector = new ASN1EncodableVector();
            timeVector.add(new Time(Date.from(signingTime)));
            attributes.put(CMSAttributes.signingTime,
                    new Attribute(CMSAttributes.signingTime, new DERSet(timeVector)));

            return new AttributeTable(attributes);

        } catch (Exception e) {
            throw new SigningFailedException("Failed to assemble PAdES signed attributes", e);
        }
    }

    /**
     * Thin wrapper that pins the Bouncy Castle provider for content signing.
     *
     * <p>Exists so the provider choice is stated once rather than repeated at
     * every call site, keeping signature generation on a known implementation
     * rather than whichever JCA provider happens to rank first.
     */
    private static final class JcaContentSignerBuilderCompat {
        private final org.bouncycastle.operator.jcajce.JcaContentSignerBuilder delegate;

        private JcaContentSignerBuilderCompat(String signatureAlgorithm) {
            this.delegate = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(PROVIDER);
        }

        private ContentSigner build(PrivateKey privateKey) throws Exception {
            return delegate.build(privateKey);
        }
    }
}
