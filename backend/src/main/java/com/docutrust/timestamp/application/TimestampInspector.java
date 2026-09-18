package com.docutrust.timestamp.application;

import java.time.Instant;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

import com.docutrust.verification.domain.TimestampStatus;

/**
 * Examines a CMS signature for an embedded RFC 3161 timestamp token.
 *
 * <h2>Why this inspects rather than assumes</h2>
 * DocuTrust signs at PAdES B-B, which carries no timestamp. It would be easy to
 * hardcode {@code NOT_AVAILABLE} on that basis — but DocuTrust verifies
 * <em>any</em> submitted PDF, including B-T documents signed by other systems.
 * Assuming no token exists would silently discard a real one and misreport a
 * stronger signature as a weaker one.
 *
 * <p>So the token is actually looked for, and three genuinely different
 * situations are reported differently:
 *
 * <ul>
 *   <li><b>NOT_AVAILABLE</b> — no token is present at all.</li>
 *   <li><b>INVALID</b> — a token is present but cannot be parsed.</li>
 *   <li><b>NOT_CHECKED</b> — a token is present and parses, but DocuTrust has no
 *       configured TSA trust anchors to validate it against.</li>
 * </ul>
 *
 * <p>That last case is the one that matters for honesty. A parseable token
 * proves only that <em>something</em> issued it. Without a trust anchor for the
 * authority, its attestation cannot be relied upon, so it is reported as
 * unchecked rather than valid. Reporting {@code VALID} here would mean trusting
 * whatever authority the document itself nominated — the same circular mistake
 * that makes trusting a document's embedded certificate chain worthless.
 */
public class TimestampInspector {

    /**
     * Result of inspecting one signature for a timestamp.
     *
     * @param status        what could be established
     * @param authorityName the TSA named in the token, or {@code null}
     * @param attestedTime  the time the TSA attested, or {@code null}
     * @param explanation   plain-language account of the finding
     */
    public record Inspection(
            TimestampStatus status,
            String authorityName,
            Instant attestedTime,
            String explanation) {
    }

    private static final Inspection ABSENT = new Inspection(
            TimestampStatus.NOT_AVAILABLE,
            null,
            null,
            "This signature carries no trusted timestamp, so the time it was created "
                    + "cannot be proven. Any signing time shown is the signer's own claim, "
                    + "not independently attested.");

    /**
     * Inspects a signature's unsigned attributes for a signature-time-stamp token.
     */
    public Inspection inspect(SignerInformation signerInformation) {
        if (signerInformation == null) {
            return ABSENT;
        }

        AttributeTable unsigned = signerInformation.getUnsignedAttributes();
        if (unsigned == null) {
            return ABSENT;
        }

        // RFC 3161 signature-time-stamp, carried as an UNSIGNED attribute -
        // necessarily so, since it is created after the signature it covers.
        Attribute attribute = unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
        if (attribute == null || attribute.getAttrValues().size() == 0) {
            return ABSENT;
        }

        try {
            ASN1Encodable value = attribute.getAttrValues().getObjectAt(0);
            TimeStampToken token = new TimeStampToken(ContentInfo.getInstance(value));

            Instant attestedTime = token.getTimeStampInfo().getGenTime().toInstant();
            String authority = describeAuthority(token);

            return new Inspection(
                    // Parseable, but not validated against any configured TSA
                    // trust anchor - so explicitly "not checked", never "valid".
                    TimestampStatus.NOT_CHECKED,
                    authority,
                    attestedTime,
                    "A timestamp token is present and attests a signing time of "
                            + attestedTime + ", but DocuTrust has no configured Timestamp "
                            + "Authority trust anchors, so the token itself has not been "
                            + "validated. It is reported as unchecked rather than valid.");

        } catch (Exception e) {
            return new Inspection(
                    TimestampStatus.INVALID,
                    null,
                    null,
                    "A timestamp token is present but could not be parsed. It is damaged "
                            + "or malformed, so no attested time can be read from it.");
        }
    }

    private String describeAuthority(TimeStampToken token) {
        try {
            var tsa = token.getTimeStampInfo().getTsa();
            if (tsa != null) {
                return tsa.getName().toString();
            }
            // The TSA field is optional; fall back to the signer identifier.
            return "Unnamed authority (serial "
                    + token.getTimeStampInfo().getSerialNumber().toString(16).toUpperCase() + ")";
        } catch (Exception e) {
            return "Unknown authority";
        }
    }
}
