package com.docutrust.common.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

import org.springframework.stereotype.Service;

/**
 * SHA-256 implementation backed by the JDK's {@link MessageDigest}.
 *
 * <p>DocuTrust implements no digest algorithm of its own (ADR-007). This class
 * is streaming plumbing around a vetted platform primitive.
 */
@Service
public class Sha256DocumentHashService implements DocumentHashService {

    private static final String ALGORITHM = "SHA-256";

    /**
     * 64 KiB. Large enough to keep syscall overhead low, small enough that
     * concurrent signing requests do not create memory pressure.
     */
    private static final int BUFFER_SIZE = 64 * 1024;

    @Override
    public String calculateSha256(InputStream inputStream) {
        Objects.requireNonNull(inputStream, "inputStream");
        MessageDigest digest = newDigest();

        // DigestInputStream updates the digest as bytes flow through, so the
        // document is never fully materialised in memory.
        try (DigestInputStream digestStream = new DigestInputStream(inputStream, digest)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            while (digestStream.read(buffer) != -1) {
                // Reading is the side effect; DigestInputStream does the work.
            }
        } catch (IOException e) {
            throw new HashingException("Failed to read document content while computing its SHA-256 digest", e);
        }

        return toHex(digest.digest());
    }

    @Override
    public String calculateSha256(byte[] content) {
        Objects.requireNonNull(content, "content");
        return toHex(newDigest().digest(content));
    }

    @Override
    public String algorithmName() {
        return ALGORITHM;
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the Java platform specification. Its
            // absence means a fundamentally broken JRE, not a runtime condition
            // any caller could meaningfully recover from.
            throw new IllegalStateException("SHA-256 unavailable; the JRE is not specification-compliant", e);
        }
    }

    private static String toHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
