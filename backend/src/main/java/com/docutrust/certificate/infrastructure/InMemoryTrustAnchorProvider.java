package com.docutrust.certificate.infrastructure;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import com.docutrust.certificate.domain.TrustAnchorProvider;

/**
 * Trust anchors held in memory.
 *
 * <p>Used by tests, which generate an ephemeral PKI per run and need to declare
 * its root trusted without writing a keystore to disk. Also backs the
 * "no anchors configured" case that produces the amber verdict.
 */
public class InMemoryTrustAnchorProvider implements TrustAnchorProvider {

    private final Set<TrustAnchor> anchors;

    public InMemoryTrustAnchorProvider(Collection<X509Certificate> trustedCertificates) {
        this.anchors = trustedCertificates == null
                ? Set.of()
                : trustedCertificates.stream()
                    // A null name-constraints argument means no additional
                    // constraints beyond those the certificate itself asserts.
                    .map(certificate -> new TrustAnchor(certificate, null))
                    .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** A provider with no anchors: nothing can ever be proven trusted. */
    public static InMemoryTrustAnchorProvider empty() {
        return new InMemoryTrustAnchorProvider(Set.of());
    }

    public static InMemoryTrustAnchorProvider of(X509Certificate... trustedCertificates) {
        return new InMemoryTrustAnchorProvider(Set.of(trustedCertificates));
    }

    @Override
    public Set<TrustAnchor> trustAnchors() {
        return Set.copyOf(anchors);
    }
}
