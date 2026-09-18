package com.docutrust.timestamp.domain;

/**
 * Obtains RFC 3161 timestamp tokens from a Timestamp Authority.
 *
 * <h2>What a timestamp is for</h2>
 * A signature carries a {@code signing-time} attribute, but the <em>signer</em>
 * chooses that value. It can say anything. Only a token from an independent
 * authority is evidence of when a signature existed.
 *
 * <p>This matters because certificates expire. Without a trusted timestamp a
 * verifier cannot distinguish a signature made while the certificate was valid
 * — legitimate, since expiry does not retroactively forge anything — from one
 * made after expiry with a key that should have been retired.
 *
 * <h2>The contract that matters</h2>
 * An implementation that cannot obtain a token must return
 * {@link TimestampResult#unavailable(String)}. It must never fabricate a token
 * or report a local clock reading as though it were attested time. Section 16
 * of the specification is explicit: when no TSA exists the status is
 * {@code NOT_AVAILABLE}, not {@code VALID}.
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@code NoOpTimestampService} — implemented; obtains nothing and says so.</li>
 *   <li>{@code Rfc3161TimestampService} — planned; would POST a
 *       {@code TimeStampReq} to a configured authority and return the token for
 *       embedding as an unsigned attribute, producing PAdES B-T.</li>
 * </ul>
 */
public interface TimestampService {

    /**
     * Requests a timestamp token over the given signature value.
     *
     * <p>The input is the CMS {@code SignerInfo} signature value, which is what
     * RFC 3161 timestamps for a signature-time-stamp attribute.
     *
     * @param signatureValue bytes to be timestamped
     * @return a token, or an explicit "unavailable" result — never a fabrication
     */
    TimestampResult timestamp(byte[] signatureValue);

    /** Whether a Timestamp Authority is configured and reachable. */
    boolean isEnabled();

    /** Identifier for reporting which authority, if any, produced a token. */
    String providerName();
}
