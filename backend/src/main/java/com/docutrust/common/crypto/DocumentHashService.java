package com.docutrust.common.crypto;

import java.io.InputStream;

/**
 * Computes content digests for documents.
 *
 * <p>Digests are the foundation of every integrity claim DocuTrust makes, so
 * this is an explicit domain capability rather than a scattered utility call.
 *
 * <p>Implementations must stream their input. Documents can be large and the
 * signing path handles them repeatedly; buffering whole files into memory is a
 * denial-of-service vector (see {@code docs/THREAT_MODEL.md}).
 */
public interface DocumentHashService {

    /**
     * Computes the SHA-256 digest of a stream and returns it as lower-case hex.
     *
     * <p>The stream is consumed but <em>not</em> closed; the caller owns it.
     *
     * @param inputStream content to digest
     * @return 64-character lower-case hex SHA-256 digest
     */
    String calculateSha256(InputStream inputStream);

    /**
     * Computes the SHA-256 digest of an in-memory byte array.
     *
     * <p>Use only where the content is already resident in memory, such as the
     * signed byte range extracted from a PDF signature dictionary.
     */
    String calculateSha256(byte[] content);

    /** Digest algorithm name, for reporting in verification output. */
    String algorithmName();
}
