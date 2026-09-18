package com.docutrust.certificate.domain;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.docutrust.common.crypto.Sha256DocumentHashService;

/**
 * Human- and machine-readable facts extracted from an X.509 certificate.
 *
 * <p>An immutable snapshot for display and reporting. It intentionally carries
 * no verdict — validity is expressed by {@link CertificateValidationResult},
 * keeping "what the certificate says" separate from "whether we trust it".
 *
 * @param subject             distinguished name of the certificate holder
 * @param issuer              distinguished name of the issuing authority
 * @param serialNumber        serial number in upper-case hex
 * @param validFrom           start of the validity window ({@code notBefore})
 * @param validUntil          end of the validity window ({@code notAfter})
 * @param publicKeyAlgorithm  e.g. {@code RSA}, {@code EC}
 * @param keySizeBits         key size in bits, or {@code null} if undetermined
 * @param signatureAlgorithm  algorithm used by the issuer to sign this certificate
 * @param sha256Fingerprint   SHA-256 over the DER encoding, lower-case hex
 * @param keyUsages           decoded KeyUsage extension values
 * @param extendedKeyUsages   decoded ExtendedKeyUsage OIDs
 * @param selfSigned          whether subject and issuer names are identical
 * @param version             X.509 version number (3 for modern certificates)
 */
public record CertificateDetails(
        String subject,
        String issuer,
        String serialNumber,
        Instant validFrom,
        Instant validUntil,
        String publicKeyAlgorithm,
        Integer keySizeBits,
        String signatureAlgorithm,
        String sha256Fingerprint,
        List<String> keyUsages,
        List<String> extendedKeyUsages,
        boolean selfSigned,
        int version
) {

    /** Bit positions of the X.509 KeyUsage extension, per RFC 5280 §4.2.1.3. */
    private static final String[] KEY_USAGE_NAMES = {
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"
    };

    public CertificateDetails {
        keyUsages = keyUsages == null ? List.of() : List.copyOf(keyUsages);
        extendedKeyUsages = extendedKeyUsages == null ? List.of() : List.copyOf(extendedKeyUsages);
    }

    /**
     * Extracts details from a parsed certificate.
     *
     * <p>All decoding is delegated to the JDK's X.509 implementation. DocuTrust
     * parses no ASN.1 itself (ADR-007).
     */
    public static CertificateDetails from(X509Certificate certificate) {
        PublicKey publicKey = certificate.getPublicKey();

        return new CertificateDetails(
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(16).toUpperCase(),
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant(),
                publicKey.getAlgorithm(),
                keySizeOf(publicKey),
                certificate.getSigAlgName(),
                fingerprintOf(certificate),
                keyUsagesOf(certificate),
                extendedKeyUsagesOf(certificate),
                certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()),
                certificate.getVersion()
        );
    }

    /** Whether the certificate's KeyUsage permits creating digital signatures. */
    public boolean permitsDigitalSignature() {
        // An absent KeyUsage extension places no restriction (RFC 5280).
        return keyUsages.isEmpty()
                || keyUsages.contains("digitalSignature")
                || keyUsages.contains("nonRepudiation");
    }

    private static Integer keySizeOf(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            return rsa.getModulus().bitLength();
        }
        if (publicKey instanceof ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize();
        }
        // Unrecognised key type: report nothing rather than guess.
        return null;
    }

    private static String fingerprintOf(X509Certificate certificate) {
        try {
            return new Sha256DocumentHashService().calculateSha256(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            // A certificate that cannot be re-encoded cannot be fingerprinted.
            return "UNAVAILABLE";
        }
    }

    private static List<String> keyUsagesOf(X509Certificate certificate) {
        boolean[] bits = certificate.getKeyUsage();
        if (bits == null) {
            return List.of();
        }
        List<String> usages = new ArrayList<>();
        for (int i = 0; i < bits.length && i < KEY_USAGE_NAMES.length; i++) {
            if (bits[i]) {
                usages.add(KEY_USAGE_NAMES[i]);
            }
        }
        return usages;
    }

    private static List<String> extendedKeyUsagesOf(X509Certificate certificate) {
        try {
            List<String> ekus = certificate.getExtendedKeyUsage();
            return ekus == null ? List.of() : List.copyOf(ekus);
        } catch (CertificateParsingException e) {
            // Malformed EKU extension: report none rather than fail the whole
            // extraction, since the rest of the certificate may still be usable.
            return List.of();
        }
    }
}
