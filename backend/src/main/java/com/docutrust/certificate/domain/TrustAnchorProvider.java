package com.docutrust.certificate.domain;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Supplies the certificates DocuTrust is willing to treat as roots of trust.
 *
 * <h2>Why this is an explicit, configured input</h2>
 * A submitted PDF embeds the signer's certificate chain. It would be trivial to
 * "validate" a signature against the chain shipped inside the same file — and
 * completely meaningless, because an attacker who forges a document also
 * controls the chain they embed in it. Self-signed forgeries would all pass.
 *
 * <p>Trust therefore comes only from anchors the operator configured out of
 * band. Certificates found inside a document are treated as claims to be
 * checked <em>against</em> these anchors, never as anchors themselves
 * (specification section 15).
 *
 * <p>An empty anchor set is a legitimate configuration: it means nothing can be
 * proven trusted, so every otherwise-valid signature resolves to the amber
 * {@code VALID_UNTRUSTED} verdict. It never means "trust everything".
 */
public interface TrustAnchorProvider {

    /**
     * The configured trust anchors.
     *
     * @return anchors; empty means no signature can reach a trusted verdict
     */
    Set<TrustAnchor> trustAnchors();

    /** Number of configured anchors, for diagnostics and the admin interface. */
    default int anchorCount() {
        return trustAnchors().size();
    }
}
