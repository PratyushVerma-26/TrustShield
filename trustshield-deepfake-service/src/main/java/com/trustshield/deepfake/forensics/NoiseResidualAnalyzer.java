package com.trustshield.deepfake.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;

/**
 * High-pass noise residual variance analyzer.
 *
 * <p>Natural optical camera sensors exhibit Photo-Response Non-Uniformity (PRNU)
 * and Poisson-Gaussian photon shot noise distributed uniformly across the entire frame.
 *
 * <p>Synthetic images (such as GAN and Diffusion models) typically lack authentic sensor
 * pattern noise, exhibiting unnatural hyper-smoothness in high-frequency residuals.
 * Conversely, composite or spliced images exhibit inconsistent noise variance across
 * different image regions, revealing donor element insertion.
 */
@Component
public class NoiseResidualAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(NoiseResidualAnalyzer.class);
    private static final int BLOCK_SIZE = 16;

    public record NoiseResidualResult(
            double variance,
            boolean anomalous,
            boolean hyperSmooth,
            String detail
    ) {}

    /**
     * Evaluates high-pass noise residual consistency and variance across 16x16 blocks.
     *
     * @param image input image
     * @param varianceThreshold threshold for inconsistent block-wise noise variance
     * @param hyperSmoothThreshold threshold below which image is considered unnaturally synthetic
     * @return NoiseResidualResult with metrics and anomaly indicators
     */
    public NoiseResidualResult analyze(BufferedImage image, double varianceThreshold, double hyperSmoothThreshold) {
        if (image == null || image.getWidth() < BLOCK_SIZE * 2 || image.getHeight() < BLOCK_SIZE * 2) {
            return new NoiseResidualResult(0.0, false, false, "Image dimensions insufficient for noise residual analysis");
        }

        int width = image.getWidth();
        int height = image.getHeight();

        // 1. Extract high-pass residual via 3x3 Laplacian kernel
        double[][] residual = new double[width][height];

        for (int y = 1; y < height - 1; y++) {
            for (int x = 1; x < width - 1; x++) {
                double center = getLuminance(image, x, y);
                double up = getLuminance(image, x, y - 1);
                double down = getLuminance(image, x, y + 1);
                double left = getLuminance(image, x - 1, y);
                double right = getLuminance(image, x + 1, y);

                // 3x3 Laplacian high-pass filter
                residual[x][y] = 4.0 * center - (up + down + left + right);
            }
        }

        // 2. Compute local noise variance for each 16x16 block
        int blocksX = (width - 2) / BLOCK_SIZE;
        int blocksY = (height - 2) / BLOCK_SIZE;

        if (blocksX == 0 || blocksY == 0) {
            return new NoiseResidualResult(0.0, false, false, "Insufficient blocks for statistical residual evaluation");
        }

        List<Double> blockVariances = new ArrayList<>(blocksX * blocksY);

        for (int by = 0; by < blocksY; by++) {
            for (int bx = 0; bx < blocksX; bx++) {
                double sum = 0.0;
                int startX = 1 + bx * BLOCK_SIZE;
                int startY = 1 + by * BLOCK_SIZE;

                for (int y = 0; y < BLOCK_SIZE; y++) {
                    for (int x = 0; x < BLOCK_SIZE; x++) {
                        sum += residual[startX + x][startY + y];
                    }
                }
                double mean = sum / (BLOCK_SIZE * BLOCK_SIZE);

                double varSum = 0.0;
                for (int y = 0; y < BLOCK_SIZE; y++) {
                    for (int x = 0; x < BLOCK_SIZE; x++) {
                        double diff = residual[startX + x][startY + y] - mean;
                        varSum += diff * diff;
                    }
                }
                blockVariances.add(varSum / (BLOCK_SIZE * BLOCK_SIZE));
            }
        }

        double meanNoiseVar = blockVariances.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);

        // Variance of block variances (measures noise inconsistency across the frame)
        double varOfVarsSum = 0.0;
        for (double v : blockVariances) {
            varOfVarsSum += (v - meanNoiseVar) * (v - meanNoiseVar);
        }
        double varianceOfNoise = blockVariances.isEmpty() ? 0.0 : (varOfVarsSum / blockVariances.size());

        boolean hyperSmooth = meanNoiseVar < hyperSmoothThreshold;
        boolean inconsistent = varianceOfNoise > varianceThreshold;
        boolean anomalous = hyperSmooth || inconsistent;

        String detail;
        if (hyperSmooth) {
            detail = String.format("Unnatural absence of optical sensor noise (mean block variance=%.2f < %.2f; characteristic of AI generation).",
                    meanNoiseVar, hyperSmoothThreshold);
        } else if (inconsistent) {
            detail = String.format("Inconsistent noise residual variance across blocks (variance=%.2f > %.2f; indicates localized splicing or composition).",
                    varianceOfNoise, varianceThreshold);
        } else {
            detail = String.format("Consistent optical noise pattern across blocks (mean=%.2f, variance=%.2f).",
                    meanNoiseVar, varianceOfNoise);
        }

        return new NoiseResidualResult(Math.round(varianceOfNoise * 100.0) / 100.0, anomalous, hyperSmooth, detail);
    }

    private double getLuminance(BufferedImage img, int x, int y) {
        int rgb = img.getRGB(x, y);
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return 0.299 * r + 0.587 * g + 0.114 * b;
    }
}
