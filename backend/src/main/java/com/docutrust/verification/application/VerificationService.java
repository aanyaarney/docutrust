package com.docutrust.verification.application;

import java.io.IOException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.util.Store;

import com.docutrust.certificate.application.CertificateValidationService;
import com.docutrust.certificate.domain.CertificateStatus;
import com.docutrust.certificate.domain.CertificateValidationResult;
import com.docutrust.certificate.domain.ChainStatus;
import com.docutrust.common.crypto.DocumentHashService;
import com.docutrust.timestamp.application.TimestampInspector;
import com.docutrust.verification.domain.IntegrityStatus;
import com.docutrust.verification.domain.SignatureStatus;
import com.docutrust.verification.domain.SignatureVerificationDetail;
import com.docutrust.verification.domain.TamperAnalysisResult;
import com.docutrust.verification.domain.TimestampStatus;
import com.docutrust.verification.domain.VerificationReport;
import com.docutrust.verification.domain.VerificationVerdict;

/**
 * Verifies PDF digital signatures and composes the overall verdict.
 *
 * <h2>How tampering is actually detected</h2>
 * Each PDF signature dictionary declares a {@code /ByteRange} naming the spans
 * of the file the signature covers — everything except the hole holding the
 * signature itself. Verification recomputes the digest over exactly those bytes
 * and compares it with the digest sealed inside the signed attributes.
 *
 * <p>If they differ, the file is provably not the file that was signed. No
 * heuristics, no comparison against a stored copy, no guessing. Changing a
 * single byte anywhere in the covered range produces a completely different
 * digest.
 *
 * <h2>Independent checks</h2>
 * Integrity, signature cryptography, certificate validity, chain trust,
 * revocation and timestamping are evaluated separately and reported separately.
 * The common failure of reporting "certificate invalid" because document text
 * changed is explicitly avoided: in that scenario the certificate is untouched
 * and still valid, and the report says so.
 */
public class VerificationService {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    static {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final DocumentHashService hashService;
    private final CertificateValidationService certificateValidationService;
    private final TamperAnalysisService tamperAnalysisService;
    private final TimestampInspector timestampInspector = new TimestampInspector();
    private final DefaultAlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();
    private final SecureRandom secureRandom = new SecureRandom();

    public VerificationService(DocumentHashService hashService,
                               CertificateValidationService certificateValidationService,
                               TamperAnalysisService tamperAnalysisService) {
        this.hashService = Objects.requireNonNull(hashService, "hashService");
        this.certificateValidationService =
                Objects.requireNonNull(certificateValidationService, "certificateValidationService");
        this.tamperAnalysisService = Objects.requireNonNull(tamperAnalysisService, "tamperAnalysisService");
    }

    /**
     * Verifies every signature in a submitted document.
     *
     * @param pdfBytes the file to verify
     * @param fileName name for reporting; must already be sanitised
     */
    public VerificationReport verify(byte[] pdfBytes, String fileName) {
        Objects.requireNonNull(pdfBytes, "pdfBytes");

        String verificationId = newVerificationId();
        Instant verifiedAt = Instant.now();
        String documentSha256 = hashService.calculateSha256(pdfBytes);

        try (PDDocument document = Loader.loadPDF(pdfBytes)) {

            List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();

            if (signatureDictionaries.isEmpty()) {
                return new VerificationReport(
                        verificationId,
                        VerificationVerdict.UNSIGNED,
                        "No digital signature present",
                        "This document carries no digital signature, so there is nothing to verify. "
                                + "Its authenticity and integrity cannot be established by cryptographic "
                                + "means. This is a statement of fact about the file, not a failure.",
                        List.of(),
                        documentSha256,
                        fileName,
                        document.getNumberOfPages(),
                        pdfBytes.length,
                        verifiedAt);
            }

            int revisionCount = countRevisions(pdfBytes);
            List<SignatureVerificationDetail> details = new ArrayList<>();

            for (int i = 0; i < signatureDictionaries.size(); i++) {
                details.add(verifySignature(signatureDictionaries.get(i), pdfBytes, i, revisionCount));
            }

            VerificationVerdict overall = combineVerdicts(details);

            return new VerificationReport(
                    verificationId,
                    overall,
                    headlineFor(overall),
                    explanationFor(overall, details),
                    details,
                    documentSha256,
                    fileName,
                    document.getNumberOfPages(),
                    pdfBytes.length,
                    verifiedAt);

        } catch (IOException e) {
            // Not a readable PDF. Explicitly neither a pass nor a fail.
            return new VerificationReport(
                    verificationId,
                    VerificationVerdict.ERROR,
                    "Document could not be read",
                    "The submitted file could not be parsed as a PDF. It may be corrupted, "
                            + "truncated, encrypted, or not a PDF at all. No conclusion about "
                            + "authenticity can be drawn.",
                    List.of(),
                    documentSha256,
                    fileName,
                    null,
                    pdfBytes.length,
                    verifiedAt);
        }
    }

    private SignatureVerificationDetail verifySignature(PDSignature signature,
                                                        byte[] pdfBytes,
                                                        int index,
                                                        int revisionCount) {
        int[] byteRange = signature.getByteRange();
        boolean coversEntireDocument = coversEntireDocument(byteRange, pdfBytes.length);
        Instant claimedSigningTime = toInstant(signature.getSignDate());
        String signatureFormat = describeFormat(signature);

        byte[] signedContent;
        byte[] cmsBytes;
        try {
            // The exact bytes the signature covers, per /ByteRange.
            signedContent = signature.getSignedContent(pdfBytes);
            cmsBytes = signature.getContents(pdfBytes);
        } catch (IOException e) {
            return corruptedDetail(signature, index, byteRange, coversEntireDocument,
                    claimedSigningTime, signatureFormat, revisionCount,
                    "The signature's byte range could not be read from the file.");
        }

        CMSSignedData cmsSignedData;
        try {
            // Detached: content supplied separately from the signature structure.
            cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), cmsBytes);
        } catch (CMSException e) {
            return corruptedDetail(signature, index, byteRange, coversEntireDocument,
                    claimedSigningTime, signatureFormat, revisionCount,
                    "The CMS signature structure could not be parsed.");
        }

        SignerInformation signerInformation = cmsSignedData.getSignerInfos().getSigners()
                .stream().findFirst().orElse(null);

        if (signerInformation == null) {
            return corruptedDetail(signature, index, byteRange, coversEntireDocument,
                    claimedSigningTime, signatureFormat, revisionCount,
                    "The CMS structure contains no signer information.");
        }

        List<X509Certificate> embeddedCertificates = extractCertificates(cmsSignedData);
        X509Certificate signerCertificate = findSignerCertificate(cmsSignedData, signerInformation);

        String digestAlgorithm = algorithmName(signerInformation.getDigestAlgOID());
        String signatureAlgorithm = describeSignatureAlgorithm(signerInformation);

        // ---- The cryptographic verification itself --------------------------
        boolean digestMismatch = false;
        boolean signatureVerified = false;
        String verificationNote = null;

        if (signerCertificate == null) {
            verificationNote = "No signer certificate was embedded in the signature.";
        } else {
            try {
                // Verify against the certificate's PUBLIC KEY rather than the
                // certificate itself.
                //
                // Bouncy Castle's certificate-based verifier additionally
                // refuses any signature whose claimed signing time falls
                // outside the certificate's validity window, reporting it as a
                // verification failure. That conflates two independent
                // questions: "is the signature mathematically sound" and "was
                // the certificate valid then". A signature made with an expired
                // certificate would be reported as a broken signature, which is
                // wrong and misleading.
                //
                // So this step answers only the mathematical question. Validity
                // windows, chain trust and revocation are evaluated separately
                // by CertificateValidationService and reported in their own
                // fields, exactly as specification sections 7 and 8 require.
                signatureVerified = signerInformation.verify(
                        new JcaSimpleSignerInfoVerifierBuilder()
                                .setProvider(BC)
                                .build(signerCertificate.getPublicKey()));
            } catch (CMSSignerDigestMismatchException e) {
                // The message-digest signed attribute does not match the digest
                // of the content. This IS the tampering signal: the bytes
                // covered by the signature are not the bytes that were signed.
                digestMismatch = true;
            } catch (Exception e) {
                verificationNote = "The signature could not be verified: " + e.getClass().getSimpleName();
            }
        }

        IntegrityStatus integrity;
        SignatureStatus signatureStatus;

        if (digestMismatch) {
            integrity = IntegrityStatus.MODIFIED;
            signatureStatus = SignatureStatus.INVALID;
        } else if (signerCertificate == null) {
            integrity = IntegrityStatus.UNKNOWN;
            signatureStatus = SignatureStatus.UNKNOWN;
        } else if (signatureVerified) {
            integrity = IntegrityStatus.INTACT;
            signatureStatus = SignatureStatus.VALID;
        } else {
            // Digest matched, so the content is intact, but the signature value
            // itself failed. A different fault entirely - and worth saying so.
            integrity = IntegrityStatus.INTACT;
            signatureStatus = SignatureStatus.INVALID;
        }

        CertificateValidationResult certificateResult = signerCertificate == null
                ? CertificateValidationResult.unavailable(
                        "No signer certificate was embedded in the signature.")
                : certificateValidationService.validate(signerCertificate, embeddedCertificates);

        TamperAnalysisResult tamperAnalysis = tamperAnalysisService.classify(new SignatureEvidence(
                true, digestMismatch, signatureVerified, coversEntireDocument, revisionCount, index));

        // Actually look for an RFC 3161 token rather than assuming none exists.
        // DocuTrust signs at B-B, but it verifies documents signed elsewhere,
        // which may well carry one.
        TimestampInspector.Inspection timestampInspection =
                timestampInspector.inspect(signerInformation);

        VerificationVerdict verdict = verdictFor(integrity, signatureStatus, certificateResult);

        return new SignatureVerificationDetail(
                index,
                signature.getName(),
                signature.getReason(),
                signature.getLocation(),
                claimedSigningTime,
                integrity,
                signatureStatus,
                certificateResult,
                timestampInspection.status(),
                timestampInspection.authorityName(),
                timestampInspection.attestedTime(),
                verificationNote == null ? tamperAnalysis
                        : new TamperAnalysisResult(tamperAnalysis.tampered(),
                                tamperAnalysis.modificationType(),
                                tamperAnalysis.explanation() + " " + verificationNote,
                                tamperAnalysis.affectedRevision(),
                                tamperAnalysis.cryptographicallyProven()),
                signatureFormat,
                digestAlgorithm,
                signatureAlgorithm,
                byteRange,
                coversEntireDocument,
                verdict);
    }

    /**
     * Composes a single signature's verdict from the independent checks.
     *
     * <p>Note the ordering: modification and signature failure dominate,
     * because they mean the document is not what it claims. Certificate and
     * trust concerns downgrade a verdict to amber but never turn a sound
     * signature red — except revocation, which is an active repudiation by the
     * issuing authority.
     */
    private VerificationVerdict verdictFor(IntegrityStatus integrity,
                                           SignatureStatus signatureStatus,
                                           CertificateValidationResult certificate) {
        if (integrity == IntegrityStatus.MODIFIED) {
            return VerificationVerdict.TAMPERED;
        }
        if (signatureStatus != SignatureStatus.VALID) {
            return VerificationVerdict.INVALID;
        }
        if (certificate.status() == CertificateStatus.REVOKED) {
            return VerificationVerdict.INVALID;
        }
        // Cryptography is sound from here on. What remains is how much identity
        // can be proven.
        if (certificate.chainStatus() != ChainStatus.TRUSTED
                || certificate.status() != CertificateStatus.VALID) {
            return VerificationVerdict.VALID_UNTRUSTED;
        }
        return VerificationVerdict.VALID;
    }

    /** The document's verdict is the worst of its signatures' verdicts. */
    private VerificationVerdict combineVerdicts(List<SignatureVerificationDetail> details) {
        VerificationVerdict worst = VerificationVerdict.VALID;
        for (SignatureVerificationDetail detail : details) {
            worst = moreSevere(worst, detail.verdict());
        }
        return worst;
    }

    private VerificationVerdict moreSevere(VerificationVerdict a, VerificationVerdict b) {
        return severity(b) > severity(a) ? b : a;
    }

    private int severity(VerificationVerdict verdict) {
        return switch (verdict) {
            case VALID -> 0;
            case VALID_UNTRUSTED -> 1;
            case UNSIGNED -> 2;
            case ERROR -> 3;
            case INVALID -> 4;
            case TAMPERED -> 5;
        };
    }

    private String headlineFor(VerificationVerdict verdict) {
        return switch (verdict) {
            case VALID -> "Authentic document";
            case VALID_UNTRUSTED -> "Valid signature — trust not established";
            case TAMPERED -> "Tampering detected";
            case INVALID -> "Invalid signature";
            case UNSIGNED -> "No digital signature present";
            case ERROR -> "Document could not be read";
        };
    }

    private String explanationFor(VerificationVerdict verdict, List<SignatureVerificationDetail> details) {
        return switch (verdict) {
            case VALID -> "The digital signature verifies, the signed content is unchanged, and the "
                    + "signer's certificate chains to a trusted authority.";
            case VALID_UNTRUSTED -> "The signature is cryptographically valid and the signed content is "
                    + "unchanged, but the signer's certificate does not chain to a configured trust "
                    + "anchor, or the certificate is outside its validity period. The document has not "
                    + "been altered; the signer's identity is simply not vouched for by an authority "
                    + "this system trusts.";
            case TAMPERED -> "This document was modified after it was digitally signed. The digest "
                    + "recomputed over the signed byte range does not match the digest recorded in the "
                    + "signature. Note that the signer's certificate may itself be perfectly valid — it "
                    + "is the document content that changed, not the certificate.";
            case INVALID -> "The signature does not verify. The content covered by the signature may be "
                    + "unchanged, but the signature value itself is not valid for this certificate.";
            case UNSIGNED -> "This document carries no digital signature.";
            case ERROR -> "The file could not be parsed as a PDF, so no conclusion can be drawn.";
        };
    }

    private SignatureVerificationDetail corruptedDetail(PDSignature signature,
                                                        int index,
                                                        int[] byteRange,
                                                        boolean coversEntireDocument,
                                                        Instant claimedSigningTime,
                                                        String signatureFormat,
                                                        int revisionCount,
                                                        String note) {
        TamperAnalysisResult analysis = tamperAnalysisService.classify(new SignatureEvidence(
                false, false, false, coversEntireDocument, revisionCount, index));

        return new SignatureVerificationDetail(
                index,
                signature.getName(),
                signature.getReason(),
                signature.getLocation(),
                claimedSigningTime,
                IntegrityStatus.UNKNOWN,
                SignatureStatus.CORRUPTED,
                CertificateValidationResult.unavailable(note),
                // The CMS could not be parsed, so its unsigned attributes -
                // where a timestamp would live - are unreadable too.
                TimestampStatus.NOT_AVAILABLE,
                null,
                null,
                new TamperAnalysisResult(analysis.tampered(), analysis.modificationType(),
                        analysis.explanation() + " " + note, analysis.affectedRevision(),
                        analysis.cryptographicallyProven()),
                signatureFormat,
                "UNKNOWN",
                "UNKNOWN",
                byteRange,
                coversEntireDocument,
                VerificationVerdict.INVALID);
    }

    private List<X509Certificate> extractCertificates(CMSSignedData signedData) {
        List<X509Certificate> certificates = new ArrayList<>();
        try {
            Store<X509CertificateHolder> store = signedData.getCertificates();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BC);
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> holders = store.getMatches(null);
            for (X509CertificateHolder holder : holders) {
                certificates.add(converter.getCertificate(holder));
            }
        } catch (Exception e) {
            // A structure whose certificates cannot be decoded yields an empty
            // pool; path building then reports INCOMPLETE rather than failing.
            return List.of();
        }
        return certificates;
    }

    private X509Certificate findSignerCertificate(CMSSignedData signedData, SignerInformation signerInformation) {
        try {
            Store<X509CertificateHolder> store = signedData.getCertificates();
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches = store.getMatches(signerInformation.getSID());
            if (matches.isEmpty()) {
                return null;
            }
            return new JcaX509CertificateConverter().setProvider(BC)
                    .getCertificate(matches.iterator().next());
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Whether the signed byte range extends to the end of the file.
     *
     * <p>{@code /ByteRange} is {@code [start1, length1, start2, length2]}. If
     * {@code start2 + length2} is short of the file length, content was
     * appended after this signature was applied.
     */
    private boolean coversEntireDocument(int[] byteRange, int fileLength) {
        if (byteRange == null || byteRange.length < 4) {
            return false;
        }
        long coveredEnd = (long) byteRange[2] + byteRange[3];
        return coveredEnd >= fileLength;
    }

    /**
     * Counts PDF revisions by counting {@code %%EOF} markers.
     *
     * <p>Best-effort structural observation, not a cryptographic measurement:
     * the marker can legitimately appear inside a stream. Used only for
     * descriptive reporting, never to decide a verdict.
     */
    private int countRevisions(byte[] pdfBytes) {
        byte[] marker = "%%EOF".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int count = 0;
        outer:
        for (int i = 0; i <= pdfBytes.length - marker.length; i++) {
            for (int j = 0; j < marker.length; j++) {
                if (pdfBytes[i + j] != marker[j]) {
                    continue outer;
                }
            }
            count++;
        }
        return Math.max(count, 1);
    }

    private String describeFormat(PDSignature signature) {
        String subFilter = signature.getSubFilter();
        if (subFilter == null) {
            return "UNKNOWN";
        }
        return switch (subFilter) {
            case "ETSI.CAdES.detached" -> "PAdES (ETSI.CAdES.detached)";
            case "ETSI.RFC3161" -> "PAdES document timestamp (ETSI.RFC3161)";
            case "adbe.pkcs7.detached" -> "Legacy PKCS#7 detached (adbe.pkcs7.detached)";
            case "adbe.pkcs7.sha1" -> "Legacy PKCS#7 SHA-1 (adbe.pkcs7.sha1)";
            default -> subFilter;
        };
    }

    /**
     * Describes the signature algorithm as a conventional JCA name, e.g.
     * {@code SHA256withRSA}.
     *
     * <p>The SignerInfo's "encryption algorithm" OID is frequently the complete
     * signature algorithm (sha256WithRSAEncryption), which Bouncy Castle
     * resolves to a full name like {@code SHA256WITHRSA}. Blindly prefixing the
     * digest onto that produces nonsense — {@code SHA256withSHA256WITHRSA} —
     * so a name that already specifies a digest is used as-is and only
     * re-cased.
     */
    private String describeSignatureAlgorithm(SignerInformation signerInformation) {
        String encryption = algorithmName(signerInformation.getEncryptionAlgOID());

        if (encryption == null || "UNKNOWN".equals(encryption)) {
            return "UNKNOWN";
        }

        if (encryption.toUpperCase(java.util.Locale.ROOT).contains("WITH")) {
            // Already a complete signature algorithm name; normalise the casing
            // to the conventional "SHA256withRSA" form.
            int index = encryption.toUpperCase(java.util.Locale.ROOT).indexOf("WITH");
            return encryption.substring(0, index) + "with" + encryption.substring(index + 4);
        }

        // A bare key algorithm (e.g. RSA, ECDSA): combine it with the digest.
        String digest = algorithmName(signerInformation.getDigestAlgOID());
        if ("UNKNOWN".equals(digest)) {
            return encryption;
        }
        return digest.replace("-", "") + "with" + encryption;
    }

    private String algorithmName(String oid) {
        try {
            String name = algorithmNameFinder.getAlgorithmName(new ASN1ObjectIdentifier(oid));
            return name == null || name.equals(oid) ? oid : name;
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private Instant toInstant(Calendar calendar) {
        return calendar == null ? null : calendar.toInstant();
    }

    /**
     * A random, non-guessable verification identifier.
     *
     * <p>Random rather than sequential so that identifiers do not leak how many
     * verifications the system has performed, and cannot be enumerated.
     */
    private String newVerificationId() {
        byte[] bytes = new byte[6];
        secureRandom.nextBytes(bytes);
        return "VER-" + HexFormat.of().formatHex(bytes).toUpperCase();
    }
}
