package com.docutrust.certificate.application;

import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.docutrust.certificate.domain.CertificateDetails;
import com.docutrust.certificate.domain.CertificateStatus;
import com.docutrust.certificate.domain.CertificateValidationResult;
import com.docutrust.certificate.domain.ChainStatus;
import com.docutrust.certificate.domain.RevocationService;
import com.docutrust.certificate.domain.RevocationStatus;
import com.docutrust.certificate.domain.TrustAnchorProvider;

/**
 * Validates a signer certificate: its structure, its validity window, its path
 * to a configured trust anchor, and its revocation status.
 *
 * <p>Deliberately more than {@code certificate.checkValidity()}, which answers
 * only "is today between two dates" and says nothing about who vouched for the
 * certificate (specification section 14).
 *
 * <h2>Why the chain is validated as of signing time</h2>
 * Path validation runs with the validation date set inside the signer
 * certificate's own validity window, not at "now". This matters because
 * expiry and trust are different questions:
 *
 * <ul>
 *   <li>A signature made in 2024 with a certificate that expired in 2025 was
 *       perfectly legitimate when made. Certificates expire; signatures made
 *       while they were valid do not retroactively become forgeries.</li>
 *   <li>Validating at "now" would report such a chain as broken, conflating
 *       "this certificate is old" with "this chain is not trustworthy".</li>
 * </ul>
 *
 * Expiry is therefore reported separately, through
 * {@link CertificateStatus#EXPIRED} and the {@code validPeriod} flag, so the
 * report can say "chain is trusted, certificate has since expired" — which is
 * both true and useful.
 *
 * <p><strong>Honest limitation:</strong> without a trusted RFC 3161 timestamp,
 * DocuTrust cannot prove <em>when</em> a signature was made. The signer's
 * claimed signing time is an unverified assertion. This is precisely why
 * timestamping exists, and why timestamp status is surfaced prominently rather
 * than buried.
 */
public class CertificateValidationService {

    private final TrustAnchorProvider trustAnchorProvider;
    private final RevocationService revocationService;

    public CertificateValidationService(TrustAnchorProvider trustAnchorProvider,
                                        RevocationService revocationService) {
        this.trustAnchorProvider = Objects.requireNonNull(trustAnchorProvider, "trustAnchorProvider");
        this.revocationService = Objects.requireNonNull(revocationService, "revocationService");
    }

    /**
     * Validates a signer certificate against the configured trust anchors.
     *
     * @param signer        the certificate to validate
     * @param intermediates additional certificates available for path building,
     *                      typically those embedded in the document's signature
     */
    public CertificateValidationResult validate(X509Certificate signer,
                                                Collection<X509Certificate> intermediates) {
        if (signer == null) {
            return CertificateValidationResult.unavailable(
                    "No signer certificate was present in the signature.");
        }

        CertificateDetails details = CertificateDetails.from(signer);
        Collection<X509Certificate> pool = intermediates == null ? List.of() : intermediates;

        // --- 1. Validity window -------------------------------------------
        Instant now = Instant.now();
        boolean notYetValid = now.isBefore(details.validFrom());
        boolean expired = now.isAfter(details.validUntil());
        boolean validPeriod = !notYetValid && !expired;

        // --- 2. Chain / trust ---------------------------------------------
        ChainStatus chainStatus = evaluateChain(signer, pool);
        List<CertificateDetails> chainDetails = describeChain(signer, pool);

        // --- 3. Revocation -------------------------------------------------
        X509Certificate issuer = findIssuer(signer, pool);
        RevocationStatus revocationStatus = revocationService.check(signer, issuer);

        // --- 4. Compose the certificate's own status -----------------------
        CertificateStatus status;
        String failureReason = null;

        if (revocationStatus.isRevoked()) {
            status = CertificateStatus.REVOKED;
            failureReason = "The certificate was reported as revoked by its issuer.";
        } else if (notYetValid) {
            status = CertificateStatus.NOT_YET_VALID;
            failureReason = "The certificate is not valid until " + details.validFrom() + ".";
        } else if (expired) {
            status = CertificateStatus.EXPIRED;
            failureReason = "The certificate expired on " + details.validUntil() + ".";
        } else if (!details.permitsDigitalSignature()) {
            status = CertificateStatus.INVALID;
            failureReason = "The certificate's KeyUsage extension does not permit digital signatures.";
        } else {
            status = CertificateStatus.VALID;
        }

        return new CertificateValidationResult(
                status, details, validPeriod, chainStatus, revocationStatus, chainDetails, failureReason);
    }

    /**
     * Attempts PKIX path construction from the signer to a configured anchor.
     */
    private ChainStatus evaluateChain(X509Certificate signer, Collection<X509Certificate> pool) {
        Set<TrustAnchor> anchors = trustAnchorProvider.trustAnchors();

        if (anchors.isEmpty()) {
            // No anchors configured: nothing can be proven trusted. Fall back to
            // describing the coherence of the chain the document supplied.
            return assessPresentedChain(signer, pool);
        }

        try {
            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(signer);

            PKIXBuilderParameters parameters = new PKIXBuilderParameters(anchors, selector);

            // Revocation is handled explicitly by RevocationService so that
            // "not checked" stays distinguishable from "checked and good".
            // Leaving PKIX's own revocation on would silently conflate them.
            parameters.setRevocationEnabled(false);

            // See the class javadoc: validate as of a moment inside the
            // signer's validity window, keeping trust orthogonal to expiry.
            parameters.setDate(Date.from(validationInstantFor(signer)));

            List<X509Certificate> candidates = new ArrayList<>(pool);
            if (!candidates.contains(signer)) {
                candidates.add(signer);
            }
            parameters.addCertStore(CertStore.getInstance(
                    "Collection", new CollectionCertStoreParameters(candidates)));

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            builder.build(parameters); // throws if no trusted path exists

            return ChainStatus.TRUSTED;

        } catch (Exception e) {
            // PKIX found no trusted path. Distinguish "coherent but not ours"
            // from "actually broken" so the report can be specific.
            return assessPresentedChain(signer, pool);
        }
    }

    /**
     * Assesses the internal coherence of the chain supplied with the document,
     * used when no trusted path could be built.
     *
     * <p>This never produces {@link ChainStatus#TRUSTED} — a chain cannot vouch
     * for itself.
     */
    private ChainStatus assessPresentedChain(X509Certificate signer, Collection<X509Certificate> pool) {
        X509Certificate current = signer;
        Set<X509Certificate> visited = new LinkedHashSet<>();

        while (true) {
            if (!visited.add(current)) {
                return ChainStatus.INVALID; // cycle
            }

            boolean selfSigned = current.getSubjectX500Principal()
                    .equals(current.getIssuerX500Principal());

            if (selfSigned) {
                try {
                    // A self-signed certificate must verify with its own key,
                    // otherwise it is simply malformed.
                    current.verify(current.getPublicKey());
                    return ChainStatus.UNTRUSTED;
                } catch (Exception e) {
                    return ChainStatus.INVALID;
                }
            }

            X509Certificate issuer = findIssuer(current, pool);
            if (issuer == null) {
                return ChainStatus.INCOMPLETE;
            }

            try {
                // Real signature verification via the JDK; the link either
                // holds mathematically or it does not.
                current.verify(issuer.getPublicKey());
            } catch (Exception e) {
                return ChainStatus.INVALID;
            }

            current = issuer;
        }
    }

    private List<CertificateDetails> describeChain(X509Certificate signer, Collection<X509Certificate> pool) {
        List<CertificateDetails> described = new ArrayList<>();
        X509Certificate current = signer;
        Set<X509Certificate> visited = new LinkedHashSet<>();

        while (current != null && visited.add(current)) {
            described.add(CertificateDetails.from(current));
            if (current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                break; // reached a self-signed root
            }
            current = findIssuer(current, pool);
        }
        return described;
    }

    /** Finds the certificate in {@code pool} whose subject matches the issuer of {@code certificate}. */
    private X509Certificate findIssuer(X509Certificate certificate, Collection<X509Certificate> pool) {
        if (certificate == null) {
            return null;
        }
        for (X509Certificate candidate : pool) {
            if (candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return candidate;
            }
        }
        // The anchor store may hold the issuer even when the document did not.
        for (TrustAnchor anchor : trustAnchorProvider.trustAnchors()) {
            X509Certificate anchorCertificate = anchor.getTrustedCert();
            if (anchorCertificate != null && anchorCertificate.getSubjectX500Principal()
                    .equals(certificate.getIssuerX500Principal())) {
                return anchorCertificate;
            }
        }
        return null;
    }

    /**
     * Chooses the instant at which to evaluate the certificate path.
     *
     * <p>Prefers the present moment, so a currently-valid certificate is judged
     * under current conditions. When the certificate is outside its window —
     * expired or not yet valid — it falls back to the last moment the
     * certificate was valid.
     *
     * <p>Choosing the <em>end</em> of the window rather than the start matters:
     * a leaf certificate is always issued during its issuer's lifetime, and
     * issuers are longer-lived than the certificates they sign. The end of a
     * leaf's window is therefore the point most likely to sit inside every
     * issuer's window too, which keeps chain evaluation about trust rather than
     * about calendar coincidence.
     */
    private Instant validationInstantFor(X509Certificate certificate) {
        Instant notBefore = certificate.getNotBefore().toInstant();
        Instant notAfter = certificate.getNotAfter().toInstant();
        Instant now = Instant.now();

        if (!now.isBefore(notBefore) && !now.isAfter(notAfter)) {
            return now;
        }
        return notAfter.minusSeconds(1);
    }
}
