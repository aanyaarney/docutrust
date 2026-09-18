package com.docutrust.common.config;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Loads trust anchors from a configured PKCS#12 trust store.
 *
 * <p>Only certificate entries are taken. A trust store containing private keys
 * is a configuration mistake, and this loader will not silently promote such an
 * entry into a trust anchor.
 */
final class TrustStoreLoader {

    private TrustStoreLoader() {
    }

    static List<X509Certificate> load(DocuTrustProperties.Trust trust) {
        if (!trust.hasTruststore()) {
            return List.of();
        }

        Path path = Path.of(trust.getTruststorePath());
        if (!Files.exists(path)) {
            throw new IllegalStateException(
                    "A trust store path is configured but no file exists there. "
                            + "Trust anchors must be present and readable, since without them no "
                            + "signature can be reported as trusted.");
        }

        try (InputStream in = Files.newInputStream(path)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, trust.getTruststorePassword().toCharArray());

            List<X509Certificate> anchors = new ArrayList<>();
            Enumeration<String> aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate x509) {
                    anchors.add(x509);
                }
            }
            return List.copyOf(anchors);

        } catch (Exception e) {
            // Never echo the password or the file contents.
            throw new IllegalStateException(
                    "Failed to load the configured trust store. Verify it is a valid PKCS#12 file "
                            + "and that the password is correct.", e);
        }
    }
}
