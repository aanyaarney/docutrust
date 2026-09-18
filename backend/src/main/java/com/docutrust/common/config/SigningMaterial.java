package com.docutrust.common.config;

import java.security.cert.X509Certificate;
import java.util.List;

import com.docutrust.signature.domain.SigningProvider;

/**
 * The key material and trust anchors the running instance was configured with.
 *
 * <p>Bundled together because they are resolved by a single decision — load a
 * configured keystore, or generate a development PKI — and must stay
 * consistent. Wiring them as independent beans would allow a configuration
 * where the signing key and the trust anchors came from different sources,
 * which would silently produce untrusted signatures.
 *
 * @param signingProvider  provider used to create signatures
 * @param trustAnchors     certificates treated as roots of trust
 * @param description      human-readable summary for startup logging
 * @param developmentOnly  whether this material is ephemeral and untrusted externally
 */
public record SigningMaterial(
        SigningProvider signingProvider,
        List<X509Certificate> trustAnchors,
        String description,
        boolean developmentOnly
) {

    public SigningMaterial {
        trustAnchors = trustAnchors == null ? List.of() : List.copyOf(trustAnchors);
    }
}
