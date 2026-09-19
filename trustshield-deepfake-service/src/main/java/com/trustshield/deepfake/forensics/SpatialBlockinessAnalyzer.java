package com.trustshield.deepfake.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.image.BufferedImage;

/**
 * Spatial 8x8 blockiness periodicity analyzer.
 *
 * <p><strong>CRITICAL ARCHITECTURAL NOTICE:</strong>
 * This blockiness measure is a <em>spatial proxy</em> and is <strong>NOT</strong>
 * DCT-histogram double-compression detection. Java's standard {@code javax.imageio.ImageIO}
 * provides no access to raw DCT coefficients or internal Huffman bitstreams. Therefore,
 * this metric evaluates spatial-domain gradient discontinuities across expected 8x8 block
 * boundaries relative to intra-block gradients.
 *
 * <p>Standard JPEG compression produces periodic boundary steps at multiples of 8 pixels
 * ($x, y \equiv 7 \pmod 8$). Spliced, rescaled, rotated, or directly synthesized AI images
 * either lack this 8x8 spatial periodicity or exhibit destructive boundary phase dissonance.
 */
@Component
public class SpatialBlockinessAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(SpatialBlockinessAnalyzer.class);

    public record BlockinessResult(
            double periodicityScore,
            boolean anomalous,
            String detail
    ) {}

    /**
     * Measures the 8x8 spatial blockiness periodicity of the provided image.
     *
     * @param image input image
     * @param periodicityThreshold threshold above which strong blockiness indicates heavy compression
     * @return BlockinessResult with calculated score and assessment
     */
    public BlockinessResult analyze(BufferedImage image, double periodicityThreshold) {
        if (image == null || image.getWidth() < 32 || image.getHeight() < 32) {
            return new BlockinessResult(0.0, false, "Image dimensions insufficient for spatial blockiness evaluation");
        }

        int width = image.getWidth();
        int height = image.getHeight();

        double boundaryGradSum = 0.0;
        long boundaryCount = 0;

        double intraGradSum = 0.0;
        long intraCount = 0;

        for (int y = 0; y < height - 1; y++) {
            boolean isYBoundary = (y % 8 == 7);
            for (int x = 0; x < width - 1; x++) {
                boolean isXBoundary = (x % 8 == 7);

                double lum = getLuminance(image, x, y);
                double lumRight = getLuminance(image, x + 1, y);
                double lumDown = getLuminance(image, x, y + 1);

                double dx = Math.abs(lumRight - lum);
                double dy = Math.abs(lumDown - lum);

                if (isXBoundary) {
                    boundaryGradSum += dx;
                    boundaryCount++;
                } else {
                    intraGradSum += dx;
                    intraCount++;
                }

                if (isYBoundary) {
                    boundaryGradSum += dy;
                    boundaryCount++;
                } else {
                    intraGradSum += dy;
                    intraCount++;
                }
            }
        }

        double avgBoundary = boundaryCount > 0 ? (boundaryGradSum / boundaryCount) : 0.0;
        double avgIntra = intraCount > 0 ? (intraGradSum / intraCount) : 0.0;

        // Ratio of boundary gradient to internal gradient
        double ratio;
        if (avgIntra > 1e-4) {
            ratio = avgBoundary / avgIntra;
        } else if (avgBoundary > 1e-4) {
            // Extreme blockiness: intra-block is completely flat while boundaries have steps
            ratio = Math.max(2.0, avgBoundary);
        } else {
            // Both boundary and intra gradients are zero (completely uniform blank image)
            ratio = 1.0;
        }

        // Normalize periodicity score: 1.0 implies uniform gradient, >1.0 indicates periodic 8x8 blocking
        double periodicityScore = Math.round(ratio * 100.0) / 100.0;

        boolean anomalous = periodicityScore > periodicityThreshold;
        String detail = String.format(
                "Spatial 8x8 blockiness proxy ratio: %.2f (boundary avg=%.2f, intra avg=%.2f). %s",
                periodicityScore,
                avgBoundary,
                avgIntra,
                anomalous
                        ? "Pronounced 8x8 block artifact periodicity detected (recompression or low-quality block grid)."
                        : "Normal spatial continuity across 8x8 grid boundaries."
        );

        return new BlockinessResult(periodicityScore, anomalous, detail);
    }

    private double getLuminance(BufferedImage img, int x, int y) {
        int rgb = img.getRGB(x, y);
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return 0.299 * r + 0.587 * g + 0.114 * b;
    }
}
