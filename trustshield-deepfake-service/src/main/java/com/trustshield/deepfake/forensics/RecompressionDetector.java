package com.trustshield.deepfake.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.image.BufferedImage;

/**
 * Recompression detector.
 *
 * <p>A recompressed image (e.g. photographs shared through messaging platforms or social media)
 * has had its original sensor noise, PRNU, and localized compression traces destroyed by
 * multi-generation transcoding and resolution downscaling.
 *
 * <p><strong>THE HONEST FAILURE INVARIANT:</strong>
 * When an image has undergone destructive recompression, the forensic signals cannot
 * establish authenticity. In accordance with the system-wide principle —
 * <em>"an unknown result is not a safe result"</em> — the service must emit
 * {@code ThreatLevel.UNKNOWN} (score 0, degraded=true) rather than falsely reporting
 * a clean bill of health.
 */
@Component
public class RecompressionDetector {

    private static final Logger log = LoggerFactory.getLogger(RecompressionDetector.class);

    public record RecompressionResult(
            boolean recompressed,
            String detail
    ) {}

    /**
     * Determines if an image has experienced destructive recompression that invalidates forensic analysis.
     *
     * @param image decoded BufferedImage
     * @param rawBytesLength length of original bytes
     * @param hasExif whether authentic EXIF metadata survived
     * @param blockinessScore spatial blockiness proxy score
     * @param noiseVariance noise residual variance
     * @param context optional context string (e.g. WHATSAPP_ATTACHMENT)
     * @return RecompressionResult indicating if traces are destroyed
     */
    public RecompressionResult evaluate(
            BufferedImage image,
            long rawBytesLength,
            boolean hasExif,
            double blockinessScore,
            double noiseVariance,
            String context
    ) {
        if (image == null) {
            return new RecompressionResult(true, "Image could not be decoded; forensic traces unavailable.");
        }

        int width = image.getWidth();
        int height = image.getHeight();
        long pixelCount = (long) width * height;

        // Byte-per-pixel ratio
        double bytesPerPixel = (pixelCount > 0) ? ((double) rawBytesLength / pixelCount) : 1.0;

        // Check 1: Explicit messaging platform context with missing EXIF
        boolean isSocialContext = context != null && (
                context.equalsIgnoreCase("WHATSAPP_ATTACHMENT") ||
                context.equalsIgnoreCase("SOCIAL_MEDIA") ||
                context.equalsIgnoreCase("COMPRESSED_PREVIEW")
        );

        if (isSocialContext && !hasExif) {
            return new RecompressionResult(
                    true,
                    "Image sent via social messaging channel with stripped EXIF and re-encoded pixel matrix; forensic traces destroyed."
            );
        }

        // Check 2: Severe compression artifact ratio (low byte density with high blockiness and stripped EXIF)
        boolean heavyCompression = (!hasExif && bytesPerPixel < 0.12 && blockinessScore > 1.30);
        if (heavyCompression) {
            return new RecompressionResult(
                    true,
                    String.format("Heavy lossy compression detected (%.3f bytes/pixel, blockiness=%.2f, no EXIF); fine forensic traces obliterated.",
                            bytesPerPixel, blockinessScore)
            );
        }

        // Check 3: Low resolution thumbnail / downscaled preview
        boolean isThumbnail = (width <= 256 || height <= 256) && !hasExif;
        if (isThumbnail) {
            return new RecompressionResult(
                    true,
                    String.format("Resolution too low (%dx%d) with stripped metadata; insufficient pixel density for forensic differentiation.", width, height)
            );
        }

        return new RecompressionResult(false, "Original forensic traces appear intact for classical analysis.");
    }
}
