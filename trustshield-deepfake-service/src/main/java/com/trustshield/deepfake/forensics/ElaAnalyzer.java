package com.trustshield.deepfake.forensics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.plugins.jpeg.JPEGImageWriteParam;
import javax.imageio.stream.ImageOutputStream;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * Error Level Analysis (ELA) analyzer.
 *
 * <p>ELA determines if an image was subjected to localized edits by re-encoding
 * the image at a known compression quality and measuring the variance of the
 * error difference across 16x16 pixel blocks.
 *
 * <p>Unmodified images generally produce uniform error distribution across blocks.
 * Locally edited, spliced, or pasted regions exhibit distinct error characteristics
 * because they have undergone a different number of compression cycles, producing
 * high block-wise variance.
 */
@Component
public class ElaAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ElaAnalyzer.class);
    private static final int BLOCK_SIZE = 16;

    public record ElaResult(double variance, boolean anomalous, String detail) {}

    /**
     * Executes Error Level Analysis on the given image at specified JPEG quality.
     *
     * @param image input image
     * @param quality JPEG compression quality (typically 0.90f)
     * @param varianceThreshold threshold above which error variance is considered anomalous
     * @return ElaResult containing measured variance and anomaly assessment
     */
    public ElaResult analyze(BufferedImage image, float quality, double varianceThreshold) {
        if (image == null || image.getWidth() < BLOCK_SIZE || image.getHeight() < BLOCK_SIZE) {
            return new ElaResult(0.0, false, "Image too small for block-wise ELA analysis");
        }

        try {
            BufferedImage rgbImage = toRgb(image);
            BufferedImage recompressed = recompress(rgbImage, quality);

            if (recompressed == null) {
                return new ElaResult(0.0, false, "Recompression failed");
            }

            int width = rgbImage.getWidth();
            int height = rgbImage.getHeight();

            int blocksX = width / BLOCK_SIZE;
            int blocksY = height / BLOCK_SIZE;

            if (blocksX == 0 || blocksY == 0) {
                return new ElaResult(0.0, false, "Insufficient blocks for statistical analysis");
            }

            List<Double> blockErrors = new ArrayList<>(blocksX * blocksY);

            for (int by = 0; by < blocksY; by++) {
                for (int bx = 0; bx < blocksX; bx++) {
                    double blockSum = 0.0;
                    for (int y = 0; y < BLOCK_SIZE; y++) {
                        int py = by * BLOCK_SIZE + y;
                        for (int x = 0; x < BLOCK_SIZE; x++) {
                            int px = bx * BLOCK_SIZE + x;

                            int rgb1 = rgbImage.getRGB(px, py);
                            int rgb2 = recompressed.getRGB(px, py);

                            double lum1 = luminance(rgb1);
                            double lum2 = luminance(rgb2);

                            blockSum += Math.abs(lum1 - lum2);
                        }
                    }
                    blockErrors.add(blockSum / (BLOCK_SIZE * BLOCK_SIZE));
                }
            }

            double mean = blockErrors.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
            double varianceSum = 0.0;
            for (double err : blockErrors) {
                varianceSum += (err - mean) * (err - mean);
            }
            double variance = blockErrors.isEmpty() ? 0.0 : varianceSum / blockErrors.size();

            boolean anomalous = variance > varianceThreshold;
            String detail = anomalous
                    ? String.format("High ELA block variance (%.2f > %.2f) indicates non-uniform compression or localized splicing", variance, varianceThreshold)
                    : String.format("Uniform ELA error distribution (variance=%.2f <= %.2f)", variance, varianceThreshold);

            return new ElaResult(variance, anomalous, detail);

        } catch (Exception e) {
            log.warn("Error during ELA analysis: {}", e.getMessage());
            return new ElaResult(0.0, false, "ELA analysis error: " + e.getMessage());
        }
    }

    private BufferedImage toRgb(BufferedImage src) {
        if (src.getType() == BufferedImage.TYPE_INT_RGB) {
            return src;
        }
        BufferedImage rgb = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = rgb.createGraphics();
        try {
            g.drawImage(src, 0, 0, null);
        } finally {
            g.dispose();
        }
        return rgb;
    }

    private BufferedImage recompress(BufferedImage rgb, float quality) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName("jpeg");
        if (!writers.hasNext()) {
            return null;
        }
        ImageWriter writer = writers.next();
        try (ImageOutputStream ios = ImageIO.createImageOutputStream(baos)) {
            writer.setOutput(ios);
            JPEGImageWriteParam param = new JPEGImageWriteParam(Locale.getDefault());
            param.setCompressionMode(ImageWriteParam.MODE_EXPLICIT);
            param.setCompressionQuality(quality);
            writer.write(null, new IIOImage(rgb, null, null), param);
        } finally {
            writer.dispose();
        }

        return ImageIO.read(new ByteArrayInputStream(baos.toByteArray()));
    }

    private double luminance(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return 0.299 * r + 0.587 * g + 0.114 * b;
    }
}
