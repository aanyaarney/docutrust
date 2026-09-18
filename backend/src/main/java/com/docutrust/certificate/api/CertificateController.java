package com.docutrust.certificate.api;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.docutrust.certificate.domain.CertificateDetails;
import com.docutrust.common.config.SigningMaterial;
import com.docutrust.signature.domain.SigningProvider;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * Describes the certificates this instance is configured with.
 *
 * <p>Exposes only public certificate data — subjects, issuers, validity windows,
 * fingerprints, key sizes. No private key material is reachable through this or
 * any other endpoint, and the signing provider interface is deliberately shaped
 * so that a private key cannot be retrieved even internally.
 */
@RestController
@RequestMapping("/api/v1/certificates")
@Tag(name = "Certificates")
public class CertificateController {

    private final SigningProvider signingProvider;
    private final SigningMaterial signingMaterial;

    public CertificateController(SigningProvider signingProvider, SigningMaterial signingMaterial) {
        this.signingProvider = signingProvider;
        this.signingMaterial = signingMaterial;
    }

    /**
     * @param signingChain  the signer chain, ordered leaf-first
     * @param trustAnchors  certificates configured as roots of trust
     * @param providerName  key custody mechanism in use
     * @param developmentPki whether this material is ephemeral and externally untrusted
     */
    public record CertificateOverview(
            List<CertificateDetails> signingChain,
            List<CertificateDetails> trustAnchors,
            String providerName,
            String description,
            boolean developmentPki) {
    }

    @GetMapping
    @Operation(summary = "Describe the configured signing chain and trust anchors")
    public CertificateOverview overview() {
        List<CertificateDetails> chain = Arrays.stream(signingProvider.certificateChain())
                .map(CertificateDetails::from)
                .toList();

        List<CertificateDetails> anchors = signingMaterial.trustAnchors().stream()
                .map(CertificateDetails::from)
                .toList();

        return new CertificateOverview(
                chain,
                anchors,
                signingProvider.providerName(),
                signingMaterial.description(),
                signingMaterial.developmentOnly());
    }

    @GetMapping("/signer")
    @Operation(summary = "Describe the signer certificate alone")
    public CertificateDetails signer() {
        X509Certificate[] chain = signingProvider.certificateChain();
        return CertificateDetails.from(chain[0]);
    }
}
