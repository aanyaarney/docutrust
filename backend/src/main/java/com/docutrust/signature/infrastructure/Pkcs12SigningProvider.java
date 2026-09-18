package com.docutrust.signature.infrastructure;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Objects;

import com.docutrust.signature.domain.SignRequest;
import com.docutrust.signature.domain.SignResult;
import com.docutrust.signature.domain.SigningFailedException;
import com.docutrust.signature.domain.SigningProvider;

/**
 * Signing provider backed by a PKCS#12 keystore on the local filesystem.
 *
 * <h2>Intended scope</h2>
 * Development and demonstration. A PKCS#12 file means the private key exists
 * as bytes on disk and is loaded into process memory — acceptable for a local
 * demo, not for production signing of consequence. Production deployments
 * should use a provider whose key never leaves an HSM or KMS boundary.
 *
 * <p>The business layer never references this class; it depends only on
 * {@link SigningProvider}.
 */
public class Pkcs12SigningProvider implements SigningProvider {

    public static final String PROVIDER_NAME = "PKCS12";

    private static final String KEYSTORE_TYPE = "PKCS12";

    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;
    private final String signatureAlgorithm;
    private final CmsSignedDataFactory cmsFactory;

    /**
     * Constructs a provider directly from key material already in memory.
     *
     * <p>Used by tests, which generate an ephemeral PKI rather than depending
     * on a keystore file existing on disk.
     */
    public Pkcs12SigningProvider(PrivateKey privateKey, X509Certificate[] certificateChain) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        this.certificateChain = Objects.requireNonNull(certificateChain, "certificateChain").clone();

        if (this.certificateChain.length == 0) {
            throw new SigningFailedException("Signing provider requires at least one certificate");
        }

        this.signatureAlgorithm = signatureAlgorithmFor(privateKey);
        this.cmsFactory = new CmsSignedDataFactory();
    }

    /**
     * Loads key material from a PKCS#12 keystore.
     *
     * @param keystorePath path to the {@code .p12} file
     * @param password     keystore and key password
     * @param alias        entry alias, or {@code null} to use the sole key entry
     */
    public static Pkcs12SigningProvider fromKeystore(Path keystorePath, char[] password, String alias) {
        Objects.requireNonNull(keystorePath, "keystorePath");
        Objects.requireNonNull(password, "password");

        if (!Files.exists(keystorePath)) {
            throw new SigningFailedException(
                    "Signing keystore not found at the configured path. "
                            + "Run `make generate-dev-cert` to create a development PKI.");
        }

        try (InputStream in = Files.newInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(in, password);

            String entryAlias = alias != null ? alias : soleKeyAlias(keyStore);

            if (!keyStore.isKeyEntry(entryAlias)) {
                throw new SigningFailedException(
                        "Keystore entry '" + entryAlias + "' does not contain a private key");
            }

            PrivateKey key = (PrivateKey) keyStore.getKey(entryAlias, password);
            Certificate[] chain = keyStore.getCertificateChain(entryAlias);

            if (chain == null || chain.length == 0) {
                throw new SigningFailedException(
                        "Keystore entry '" + entryAlias + "' has no associated certificate chain");
            }

            X509Certificate[] x509Chain = Arrays.stream(chain)
                    .map(X509Certificate.class::cast)
                    .toArray(X509Certificate[]::new);

            return new Pkcs12SigningProvider(key, x509Chain);

        } catch (SigningFailedException e) {
            throw e;
        } catch (IOException e) {
            // Deliberately does not echo the path's full contents or the
            // password. A wrong password surfaces here as an IOException.
            throw new SigningFailedException(
                    "Could not read the signing keystore. Verify the file is a valid PKCS#12 "
                            + "and that the configured password is correct.", e);
        } catch (Exception e) {
            throw new SigningFailedException("Failed to load signing key material from the keystore", e);
        }
    }

    @Override
    public SignResult sign(SignRequest request) {
        Objects.requireNonNull(request, "request");

        byte[] cms = cmsFactory.buildDetachedSignature(
                request.contentToSign(),
                privateKey,
                certificateChain,
                signatureAlgorithm,
                request.signingTime());

        return new SignResult(
                cms,
                certificateChain[0],
                signatureAlgorithm,
                request.digestAlgorithm(),
                request.signingTime(),
                PROVIDER_NAME);
    }

    @Override
    public String providerName() {
        return PROVIDER_NAME;
    }

    @Override
    public X509Certificate[] certificateChain() {
        return certificateChain.clone();
    }

    @Override
    public boolean isAvailable() {
        return privateKey != null && certificateChain.length > 0;
    }

    /** The signer certificate (leaf of the chain). */
    public X509Certificate signerCertificate() {
        return certificateChain[0];
    }

    /**
     * Selects a signature algorithm matching the key type.
     *
     * <p>SHA-256 is the digest in both cases: it is the PAdES baseline default
     * and has no known practical collision attack, unlike SHA-1, whose use in
     * signatures is deprecated precisely because collisions enable substituting
     * one signed document for another.
     */
    private static String signatureAlgorithmFor(PrivateKey key) {
        return switch (key.getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC", "ECDSA" -> "SHA256withECDSA";
            default -> throw new SigningFailedException(
                    "Unsupported signing key algorithm: " + key.getAlgorithm()
                            + ". DocuTrust supports RSA and ECDSA.");
        };
    }

    private static String soleKeyAlias(KeyStore keyStore) throws Exception {
        String found = null;
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String candidate = aliases.nextElement();
            if (keyStore.isKeyEntry(candidate)) {
                if (found != null) {
                    throw new SigningFailedException(
                            "Keystore contains multiple key entries; configure an explicit alias");
                }
                found = candidate;
            }
        }
        if (found == null) {
            throw new SigningFailedException("Keystore contains no private key entry");
        }
        return found;
    }
}
