package com.docutrust.certificate.devpki;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Writes a generated development PKI to PKCS#12 files on disk.
 *
 * <p>Invoked by {@code make generate-dev-cert}. Produces:
 * <ul>
 *   <li>{@code signer.p12} — signer private key and its full chain</li>
 *   <li>{@code truststore.p12} — the root CA certificate only, no private key</li>
 * </ul>
 *
 * <h2>Why this is Java rather than an OpenSSL shell script</h2>
 * The specification suggests shell scripts under {@code scripts/pki/}. This is
 * implemented in Java instead because OpenSSL is not present on a default
 * Windows installation, and a PKI generator that only runs on Unix would leave
 * a Windows developer unable to start. The same Bouncy Castle code already
 * backs the test suite, so there is one implementation to keep correct rather
 * than two. An equivalent OpenSSL sequence is documented in
 * {@code docs/CRYPTOGRAPHY.md} for anyone who prefers it.
 *
 * <h2>Password handling</h2>
 * The keystore password comes from {@code DOCUTRUST_PKCS12_PASSWORD} when set.
 * Otherwise a random one is generated and printed once, because a hardcoded
 * default password on a key file is indistinguishable from no password at all.
 *
 * <p>The output directory is gitignored. These keys are for local development
 * and carry no external trust.
 */
public final class DevPkiWriter {

    private static final String SIGNER_ALIAS = "docutrust-signer";
    private static final String ROOT_ALIAS = "docutrust-dev-root";

    private DevPkiWriter() {
    }

    public static void main(String[] args) throws Exception {
        Path outputDir = Path.of(args.length > 0 ? args[0] : "pki-local");
        Files.createDirectories(outputDir);

        String configured = System.getenv("DOCUTRUST_PKCS12_PASSWORD");
        boolean generated = configured == null || configured.isBlank();
        char[] password = (generated ? randomPassword() : configured).toCharArray();

        DevPkiGenerator.DevPki pki = new DevPkiGenerator().generateThreeTierPki();

        // --- signer keystore: private key plus the chain that proves it -----
        KeyStore signerStore = KeyStore.getInstance("PKCS12");
        signerStore.load(null, password);
        signerStore.setKeyEntry(SIGNER_ALIAS, pki.signer().privateKey(), password, pki.signerChain());

        Path signerPath = outputDir.resolve("signer.p12");
        try (OutputStream out = Files.newOutputStream(signerPath)) {
            signerStore.store(out, password);
        }

        // --- trust store: the root CERTIFICATE only ------------------------
        // Deliberately no private key. A trust store answers "whom do we
        // trust", and a root private key sitting beside the application it
        // vouches for would let anyone who reaches the file issue certificates
        // the system then trusts.
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, password);
        trustStore.setCertificateEntry(ROOT_ALIAS, pki.root().certificate());

        Path trustPath = outputDir.resolve("truststore.p12");
        try (OutputStream out = Files.newOutputStream(trustPath)) {
            trustStore.store(out, password);
        }

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.println("  DEVELOPMENT PKI WRITTEN");
        System.out.println("=".repeat(70));
        System.out.printf("  Signer keystore : %s%n", signerPath.toAbsolutePath());
        System.out.printf("  Trust store     : %s%n", trustPath.toAbsolutePath());
        System.out.printf("  Signer subject  : %s%n", pki.signer().certificate().getSubjectX500Principal());
        System.out.printf("  Issuing CA      : %s%n", pki.intermediate().certificate().getSubjectX500Principal());
        System.out.printf("  Root CA         : %s%n", pki.root().certificate().getSubjectX500Principal());
        System.out.println();

        if (generated) {
            System.out.println("  Generated password (shown once - store it in .env):");
            System.out.printf("    DOCUTRUST_PKCS12_PASSWORD=%s%n", new String(password));
            System.out.printf("    DOCUTRUST_TRUSTSTORE_PASSWORD=%s%n", new String(password));
        } else {
            System.out.println("  Password taken from DOCUTRUST_PKCS12_PASSWORD.");
        }

        System.out.println();
        System.out.println("  These keys are for local development only. They are");
        System.out.println("  gitignored, carry no external trust, and must never be");
        System.out.println("  used to sign anything of legal or commercial value.");
        System.out.println("=".repeat(70));

        // Clear the password from memory. Not a complete defence - String
        // instances created along the way may persist until collected - but
        // it avoids leaving the array itself readable for the process lifetime.
        java.util.Arrays.fill(password, '\0');
    }

    private static String randomPassword() {
        byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
