package com.docutrust.signature.infrastructure;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import javax.imageio.ImageIO;

import com.docutrust.signature.domain.SigningFailedException;

/**
 * Draws the visible signature block that appears on the signed page.
 *
 * <h2>This mark is informational, not evidence</h2>
 * The image produced here proves nothing. It is ordinary page content: anybody
 * can draw the same rectangle in any PDF editor, and a forged document can
 * carry a perfect-looking block. What makes a signature real is the CMS
 * structure in the signature dictionary and the digest over the signed byte
 * range — none of which a reader can see.
 *
 * <p>Two consequences are deliberately built in:
 *
 * <ul>
 *   <li>The block never uses words like "verified", "authentic" or a tick mark
 *       that would imply a verification has taken place. It states who signed
 *       and when they claimed to, and directs the reader to verify.</li>
 *   <li>It carries the wording "Verify at DocuTrust — appearance alone proves
 *       nothing", so the artefact itself tells a reader not to trust it.</li>
 * </ul>
 *
 * Specification section 6 requires exactly this: that modifying the visible
 * text cannot be mistaken for cryptographic verification. Since the block sits
 * inside the signed byte range, editing it actually <em>breaks</em> the
 * signature — but a reader cannot know that by looking, which is the point.
 *
 * <h2>Why a raster image</h2>
 * PDFBox's visible-signature support takes an image. It is rendered at four
 * times the final size and scaled down, so text stays crisp when a reader zooms
 * in rather than turning into the blurry stamp these blocks usually become.
 */
public class VisibleSignatureRenderer {

    /** Final size on the page, in PDF points (1/72 inch). */
    private static final int WIDTH_POINTS = 190;
    private static final int HEIGHT_POINTS = 70;

    /** Supersampling factor. Raster stamps look cheap mainly because of this. */
    private static final int SCALE = 4;

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm z");

    private static final Color INK = new Color(0x11, 0x39, 0x7A);
    private static final Color TEXT = new Color(0x1E, 0x28, 0x3C);
    private static final Color MUTED = new Color(0x6B, 0x73, 0x84);
    private static final Color BORDER = new Color(0x11, 0x39, 0x7A, 0x66);

    /**
     * Renders the block as a PNG.
     *
     * @param signerName  name to display; a fallback is used when absent
     * @param signingTime claimed signing time
     * @param reason      optional stated reason
     * @param zoneId      zone used to present the time to a reader
     * @return PNG bytes, ready for PDFBox's visible signature support
     */
    public InputStream render(String signerName, Instant signingTime, String reason, ZoneId zoneId) {
        int width = WIDTH_POINTS * SCALE;
        int height = HEIGHT_POINTS * SCALE;

        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();

        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                    RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

            // Transparent background so the block does not obscure page content
            // it happens to overlap.
            g.setColor(new Color(255, 255, 255, 235));
            g.fillRoundRect(0, 0, width - SCALE, height - SCALE, 6 * SCALE, 6 * SCALE);

            g.setColor(BORDER);
            g.setStroke(new BasicStroke(SCALE));
            g.drawRoundRect(0, 0, width - SCALE, height - SCALE, 6 * SCALE, 6 * SCALE);

            // Accent bar on the left edge.
            g.setColor(INK);
            g.fillRect(0, SCALE, 3 * SCALE, height - 3 * SCALE);

            int x = 10 * SCALE;
            int y = 14 * SCALE;

            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 7 * SCALE));
            g.setColor(MUTED);
            g.drawString("DIGITALLY SIGNED BY", x, y);

            y += 12 * SCALE;
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 10 * SCALE));
            g.setColor(TEXT);
            g.drawString(truncate(signerName == null || signerName.isBlank()
                    ? "Unnamed signer" : signerName, 24), x, y);

            y += 11 * SCALE;
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 7 * SCALE));
            g.setColor(MUTED);
            g.drawString(DATE_FORMAT.format(signingTime.atZone(zoneId)), x, y);

            if (reason != null && !reason.isBlank()) {
                y += 9 * SCALE;
                g.drawString(truncate(reason, 34), x, y);
            }

            // The disclaimer. A visible block that merely asserted "verified"
            // would be teaching readers the exact habit this product exists to
            // break.
            y = height - 8 * SCALE;
            g.setFont(new Font(Font.SANS_SERIF, Font.ITALIC, 6 * SCALE));
            g.setColor(MUTED);
            g.drawString("Appearance proves nothing - verify this document", x, y);

        } finally {
            g.dispose();
        }

        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return new ByteArrayInputStream(out.toByteArray());
        } catch (IOException e) {
            throw new SigningFailedException("Failed to render the visible signature block", e);
        }
    }

    /** Width of the block on the page, in points. */
    public int widthPoints() {
        return WIDTH_POINTS;
    }

    /** Height of the block on the page, in points. */
    public int heightPoints() {
        return HEIGHT_POINTS;
    }

    private String truncate(String value, int maxLength) {
        if (value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength - 1) + "…";
    }
}
