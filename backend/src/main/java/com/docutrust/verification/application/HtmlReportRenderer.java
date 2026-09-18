package com.docutrust.verification.application;

import java.time.format.DateTimeFormatter;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAccessor;

import com.docutrust.certificate.domain.CertificateDetails;
import com.docutrust.certificate.domain.CertificateValidationResult;
import com.docutrust.verification.domain.SignatureVerificationDetail;
import com.docutrust.verification.domain.VerificationReport;

/**
 * Renders a verification report as a standalone HTML document.
 *
 * <h2>Escaping</h2>
 * Every interpolated value is HTML-escaped. This is not decoration: the file
 * name comes from whoever uploaded the document, and certificate subjects come
 * from whoever issued the certificate — both attacker-controlled. A report
 * containing an unescaped {@code <script>} from a hostile filename would turn a
 * security report into a delivery mechanism for stored cross-site scripting, in
 * a document people are specifically inclined to trust.
 *
 * <p>The output is self-contained: inline styles, no external requests. A
 * report that phones out for a stylesheet would leak to a third party every
 * time somebody opened it, and would look wrong offline.
 */
public class HtmlReportRenderer {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    public String render(VerificationReport report) {
        StringBuilder html = new StringBuilder(8192);

        html.append("<!doctype html>\n<html lang=\"en\">\n<head>\n")
            .append("<meta charset=\"utf-8\">\n")
            .append("<title>DocuTrust Verification Report ")
            .append(escape(report.verificationId())).append("</title>\n")
            .append(styles())
            .append("</head>\n<body>\n<div class=\"page\">\n");

        // ---- header ----
        html.append("<header>\n")
            .append("<h1>DocuTrust Verification Report</h1>\n")
            .append("<p class=\"sub\">Cryptographic verification of a PDF digital signature</p>\n")
            .append("</header>\n");

        // ---- verdict ----
        String tone = toneFor(report.verdict().name());
        html.append("<section class=\"verdict ").append(tone).append("\">\n")
            .append("<div class=\"verdict-label\">").append(escape(report.headline())).append("</div>\n")
            .append("<p>").append(escape(report.explanation())).append("</p>\n")
            .append("</section>\n");

        // ---- document ----
        html.append("<section>\n<h2>Document</h2>\n<table>\n");
        row(html, "File name", report.fileName());
        row(html, "Size", report.fileSizeBytes() + " bytes");
        row(html, "Pages", report.pageCount() == null ? "Unknown" : String.valueOf(report.pageCount()));
        monoRow(html, "SHA-256 of submitted file", report.documentSha256());
        html.append("</table>\n</section>\n");

        // ---- per-signature ----
        if (report.signatures().isEmpty()) {
            html.append("<section>\n<h2>Signatures</h2>\n")
                .append("<p class=\"muted\">This document carries no digital signature, "
                        + "so there is nothing to verify.</p>\n</section>\n");
        }

        int index = 1;
        for (SignatureVerificationDetail signature : report.signatures()) {
            renderSignature(html, signature, index++, report.signatures().size());
        }

        // ---- footer ----
        html.append("<footer>\n")
            .append("<table>\n");
        monoRow(html, "Verification ID", report.verificationId());
        row(html, "Verified at", format(report.verifiedAt()));
        html.append("</table>\n")
            .append("<p class=\"disclaimer\">This report describes standards-based ")
            .append("cryptographic verification. It is not a legal attestation. ")
            .append("A valid signature proves a document is unchanged since signing; ")
            .append("it does not establish that the document's contents are true.</p>\n")
            .append("</footer>\n");

        html.append("</div>\n</body>\n</html>\n");
        return html.toString();
    }

    private void renderSignature(StringBuilder html, SignatureVerificationDetail signature,
                                 int position, int total) {
        html.append("<section>\n<h2>")
            .append(total > 1 ? "Signature " + position + " of " + total : "Signature")
            .append("</h2>\n");

        CertificateValidationResult certificate = signature.certificate();

        // The six independent checks, each reported separately.
        html.append("<table class=\"checks\">\n");
        checkRow(html, "Document integrity", signature.integrity().name());
        checkRow(html, "Digital signature", signature.signature().name());
        checkRow(html, "Certificate", certificate.status().name());
        checkRow(html, "Certificate chain", certificate.chainStatus().name());
        checkRow(html, "Trusted timestamp", signature.timestamp().name());
        checkRow(html, "Revocation", certificate.revocationStatus().name());
        html.append("</table>\n");

        // Tamper analysis, with proof separated from interpretation.
        html.append("<h3>Modification analysis</h3>\n<table>\n");
        row(html, "Classification", signature.tamperAnalysis().modificationType().name());
        row(html, "Evidence", signature.tamperAnalysis().cryptographicallyProven()
                ? "Cryptographically proven"
                : "Best-effort structural observation, not proof");
        html.append("</table>\n<p class=\"muted\">")
            .append(escape(signature.tamperAnalysis().explanation()))
            .append("</p>\n");

        // Signer.
        if (certificate.details() != null) {
            CertificateDetails details = certificate.details();
            html.append("<h3>Signer certificate</h3>\n<table>\n");
            row(html, "Subject", details.subject());
            row(html, "Issuer", details.issuer());
            monoRow(html, "Serial number", details.serialNumber());
            row(html, "Valid from", format(details.validFrom()));
            row(html, "Valid until", format(details.validUntil()));
            row(html, "Public key", details.keySizeBits() == null
                    ? details.publicKeyAlgorithm()
                    : details.publicKeyAlgorithm() + " " + details.keySizeBits() + " bits");
            row(html, "Certificate signature", details.signatureAlgorithm());
            monoRow(html, "SHA-256 fingerprint", details.sha256Fingerprint());
            row(html, "Key usage", details.keyUsages().isEmpty()
                    ? "Not restricted" : String.join(", ", details.keyUsages()));
            html.append("</table>\n");
        }

        // Cryptographic detail.
        html.append("<h3>Cryptographic details</h3>\n<table>\n");
        row(html, "Signature format", signature.signatureFormat());
        row(html, "Digest algorithm", signature.digestAlgorithm());
        row(html, "Signature algorithm", signature.signatureAlgorithm());
        monoRow(html, "Signed byte range", signature.byteRangeDisplay());
        row(html, "Covers whole document", signature.coversEntireDocument()
                ? "Yes" : "No - content follows this signature");
        row(html, "Claimed signing time", signature.claimedSigningTime() == null
                ? "Not stated"
                : format(signature.claimedSigningTime()) + " (asserted by signer, not proven)");
        row(html, "Timestamp authority", signature.timestampAuthority() == null
                ? "None - no timestamp token present" : signature.timestampAuthority());
        row(html, "Attested time", signature.timestampAttestedTime() == null
                ? "None - the time of signing cannot be proven"
                : format(signature.timestampAttestedTime()));
        html.append("</table>\n</section>\n");
    }

    private void row(StringBuilder html, String label, String value) {
        html.append("<tr><th>").append(escape(label)).append("</th><td>")
            .append(escape(value == null ? "Not available" : value)).append("</td></tr>\n");
    }

    private void monoRow(StringBuilder html, String label, String value) {
        html.append("<tr><th>").append(escape(label)).append("</th><td class=\"mono\">")
            .append(escape(value == null ? "Not available" : value)).append("</td></tr>\n");
    }

    private void checkRow(StringBuilder html, String label, String status) {
        html.append("<tr><th>").append(escape(label)).append("</th><td>")
            .append("<span class=\"badge ").append(toneFor(status)).append("\">")
            .append(escape(readable(status))).append("</span></td></tr>\n");
    }

    /**
     * Maps a status to a visual tone.
     *
     * <p>Anything not affirmatively good is neutral or bad — never green. The
     * set of green statuses is enumerated explicitly rather than derived by
     * exclusion, so a status added later defaults to neutral instead of
     * silently rendering as a pass.
     */
    private String toneFor(String status) {
        return switch (status) {
            case "VALID", "INTACT", "TRUSTED", "GOOD" -> "good";
            case "VALID_UNTRUSTED", "EXPIRED", "NOT_YET_VALID", "UNTRUSTED", "INCOMPLETE" -> "warn";
            case "TAMPERED", "INVALID", "MODIFIED", "CORRUPTED", "REVOKED" -> "bad";
            default -> "neutral";
        };
    }

    private String readable(String status) {
        String lower = status.replace('_', ' ').toLowerCase();
        return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
    }

    private String format(TemporalAccessor instant) {
        return instant == null ? "Not available" : TIMESTAMP_FORMAT.format(instant);
    }

    /** Escapes the five characters that can break out of HTML text or attributes. */
    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String styles() {
        return """
                <style>
                  :root { color-scheme: light; }
                  body { margin: 0; background: #f5f7fa; color: #11192b;
                         font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                         line-height: 1.55; }
                  .page { max-width: 820px; margin: 0 auto; padding: 32px 20px 64px; }
                  header { border-bottom: 3px solid #11397a; padding-bottom: 14px; margin-bottom: 26px; }
                  h1 { margin: 0; font-size: 25px; letter-spacing: -0.02em; color: #11397a; }
                  .sub { margin: 4px 0 0; color: #5b6472; font-size: 14px; }
                  h2 { font-size: 17px; margin: 30px 0 10px; }
                  h3 { font-size: 14px; margin: 22px 0 8px; color: #39414d;
                       text-transform: uppercase; letter-spacing: 0.06em; }
                  section { background: #fff; border: 1px solid rgba(17,25,40,0.10);
                            border-radius: 10px; padding: 18px 20px; margin-bottom: 16px; }
                  .verdict { border-left: 6px solid; }
                  .verdict-label { font-size: 22px; font-weight: 700; margin-bottom: 6px; }
                  .verdict p { margin: 0; font-size: 14px; }
                  .verdict.good { border-left-color: #1b873f; background: #e7f5ec; }
                  .verdict.good .verdict-label { color: #12652d; }
                  .verdict.warn { border-left-color: #b26a00; background: #fdf3e3; }
                  .verdict.warn .verdict-label { color: #8a5200; }
                  .verdict.bad  { border-left-color: #c62828; background: #fdeded; }
                  .verdict.bad .verdict-label { color: #9b1c1c; }
                  .verdict.neutral { border-left-color: #5b6472; background: #eef1f5; }
                  table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
                  th { text-align: left; font-weight: 600; color: #5b6472; width: 210px;
                       vertical-align: top; padding: 5px 12px 5px 0; }
                  td { padding: 5px 0; vertical-align: top; word-break: break-word; }
                  .mono { font-family: Consolas, "SF Mono", monospace; font-size: 12.5px; }
                  .badge { display: inline-block; padding: 2px 10px; border-radius: 20px;
                           font-size: 12px; font-weight: 700; }
                  .badge.good { background: #1b873f; color: #fff; }
                  .badge.warn { background: #b26a00; color: #fff; }
                  .badge.bad  { background: #c62828; color: #fff; }
                  .badge.neutral { background: #eef1f5; color: #39414d;
                                   border: 1px solid rgba(17,25,40,0.18); }
                  .muted { color: #5b6472; font-size: 13px; }
                  footer { margin-top: 26px; padding-top: 16px;
                           border-top: 1px solid rgba(17,25,40,0.12); }
                  .disclaimer { color: #5b6472; font-size: 12px; margin-top: 14px; }
                  @media print { body { background: #fff; } section { break-inside: avoid; } }
                </style>
                """;
    }
}
