package com.docutrust.signature.domain;

import java.security.cert.X509Certificate;

/**
 * Abstraction over whatever holds the signing key.
 *
 * <p>This is the seam that keeps the business layer independent of key storage.
 * Nothing above this interface knows whether the private key lives in a
 * PKCS#12 file, a SoftHSM token, or AWS KMS.
 *
 * <h2>Why the contract is shaped this way</h2>
 * The interface takes content and returns a complete CMS SignedData structure,
 * rather than exposing the {@link java.security.PrivateKey} itself. That
 * matters: an HSM or cloud KMS will never hand out the private key. The only
 * operation such a device offers is "sign these bytes", and the key must never
 * cross the boundary. Designing around key retrieval would make those
 * providers impossible to implement without weakening their security model.
 *
 * <p>Implementations are responsible for the signature operation and for
 * supplying their certificate chain. CMS assembly itself is shared — see
 * {@code CmsSignedDataFactory} — so that providers differ only in how the raw
 * signature is produced.
 *
 * <h2>Implementations</h2>
 * <ul>
 *   <li>{@code Pkcs12SigningProvider} — implemented; development and demonstration.</li>
 *   <li>{@code SoftHsmSigningProvider} — planned; PKCS#11 token.</li>
 *   <li>{@code AwsKmsSigningProvider}, {@code AzureKeyVaultSigningProvider},
 *       {@code GoogleCloudKmsSigningProvider} — planned; see
 *       {@code docs/KMS_INTEGRATION.md}.</li>
 *   <li>{@code IndiaESignProvider} — design only. Not implemented, and
 *       deliberately not stubbed to appear functional.</li>
 * </ul>
 */
public interface SigningProvider {

    /**
     * Produces a detached CMS SignedData structure over the supplied content.
     *
     * @param request content to sign and the parameters governing the signature
     * @return the CMS structure plus the facts needed to report what was done
     * @throws SigningFailedException if the signature could not be produced
     */
    SignResult sign(SignRequest request);

    /**
     * Stable identifier for this provider, recorded in audit entries and
     * surfaced in signing results so operators can tell which key custody
     * mechanism produced a given signature.
     */
    String providerName();

    /**
     * The signer's certificate chain, ordered leaf-first.
     *
     * <p>Embedded into the CMS structure so verifiers can build a path.
     */
    X509Certificate[] certificateChain();

    /**
     * Whether this provider is configured and its key material is reachable.
     *
     * <p>Checked at startup so that a misconfigured keystore surfaces as a
     * clear diagnostic rather than as a failure on the first signing attempt.
     */
    boolean isAvailable();
}
