package com.trustshield.fakenews.multimodal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Visual forensics analyzer for television news chyrons, lower-third tickers, and breaking news banners.
 *
 * <p>Identifies broadcast news layouts and detects digital tampering, font step discontinuities,
 * and spliced typography commonly found in fabricated television screenshot hoaxes.
 */
@Component
public class NewsChyronAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(NewsChyronAnalyzer.class);

    private final double anomalyThreshold;

    public record ChyronAnalysis(
            boolean chyronDetected,
            boolean splicedOrManipulated,
            String bannerType,
            double anomalyScore,
            List<String> anomalies,
            String extractedBannerText
    ) {
        public static ChyronAnalysis clean() {
            return new ChyronAnalysis(false, false, "NONE", 0.0, List.of(), null);
        }
    }

    public NewsChyronAnalyzer(
            @Value("${trustshield.fakenews.multimodal.chyron-anomaly-threshold:0.65}") double anomalyThreshold) {
        this.anomalyThreshold = anomalyThreshold;
    }

    /**
     * Evaluates an image byte payload for TV news chyron layouts and tampering artifacts.
     */
    public ChyronAnalysis analyze(byte[] imageBytes, String filename) {
        if (imageBytes == null || imageBytes.length == 0) {
            return ChyronAnalysis.clean();
        }

        List<String> anomalies = new ArrayList<>();
        String extractedBanner = scanAsciiChyronKeywords(imageBytes);
        boolean chyronDetected = extractedBanner != null;
        String bannerType = "NONE";
        double anomalyScore = 0.0;
        boolean spliced = false;

        try {
            BufferedImage img = ImageIO.read(new ByteArrayInputStream(imageBytes));
            if (img != null) {
                int width = img.getWidth();
                int height = img.getHeight();

                if (width >= 100 && height >= 60) {
                    // Check lower-third region (bottom 25% of frame)
                    int lowerThirdY = (int) (height * 0.75);
                    int lowerThirdHeight = height - lowerThirdY;

                    ChyronBandScan bandScan = scanLowerThirdBands(img, lowerThirdY, lowerThirdHeight, width);
                    if (bandScan.bandDetected) {
                        chyronDetected = true;
                        bannerType = bandScan.detectedStyle;

                        // Check for splice discontinuity artifacts in the banner region
                        double spliceVariance = calculateTextRegionSpliceVariance(img, lowerThirdY, lowerThirdHeight, width);
                        if (spliceVariance >= anomalyThreshold) {
                            spliced = true;
                            anomalyScore = spliceVariance;
                            anomalies.add(String.format(Locale.ROOT,
                                    "Font step discontinuity detected in lower-third banner (score: %.2f)", spliceVariance));
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.debug("ImageIO decoding skipped or failed: {}", e.getMessage());
        }

        // Check if banner text contains common breaking news tropes
        if (extractedBanner != null) {
            if (bannerType.equals("NONE")) {
                bannerType = "BREAKING_NEWS_OVERLAY";
            }
            if (extractedBanner.toLowerCase(Locale.ROOT).contains("breaking") ||
                extractedBanner.toLowerCase(Locale.ROOT).contains("urgent") ||
                extractedBanner.toLowerCase(Locale.ROOT).contains("exclusive")) {
                if (anomalyScore < 0.3) {
                    anomalyScore = 0.35;
                }
            }
        }

        return new ChyronAnalysis(chyronDetected, spliced, bannerType, anomalyScore, anomalies, extractedBanner);
    }

    private record ChyronBandScan(boolean bandDetected, String detectedStyle) {}

    private ChyronBandScan scanLowerThirdBands(BufferedImage img, int startY, int bandH, int width) {
        int redHits = 0;
        int navyHits = 0;
        int yellowHits = 0;
        int sampleCount = 0;

        // Sample horizontal rows across lower-third
        int step = Math.max(1, bandH / 10);
        int colStep = Math.max(1, width / 40);

        for (int y = startY; y < startY + bandH; y += step) {
            for (int x = 0; x < width; x += colStep) {
                sampleCount++;
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Breaking news red banner: R > 150, G < 65, B < 65
                if (r > 150 && g < 65 && b < 65) {
                    redHits++;
                }
                // Broadcast navy lower-third: R < 55, G < 85, B > 130
                else if (r < 55 && g < 85 && b > 130) {
                    navyHits++;
                }
                // Ticker yellow banner: R > 180, G > 160, B < 60
                else if (r > 180 && g > 160 && b < 60) {
                    yellowHits++;
                }
            }
        }

        if (sampleCount == 0) {
            return new ChyronBandScan(false, "NONE");
        }

        double redRatio = (double) redHits / sampleCount;
        double navyRatio = (double) navyHits / sampleCount;
        double yellowRatio = (double) yellowHits / sampleCount;

        if (redRatio >= 0.18) {
            return new ChyronBandScan(true, "BREAKING_NEWS_RED_BANNER");
        }
        if (navyRatio >= 0.20) {
            return new ChyronBandScan(true, "LOWER_THIRD_NAVY_BANNER");
        }
        if (yellowRatio >= 0.15) {
            return new ChyronBandScan(true, "TICKER_YELLOW_CRAWL");
        }

        return new ChyronBandScan(false, "NONE");
    }

    /**
     * Measures local gradient discontinuity and edge noise variance inside the lower third.
     * Spliced fake chyrons show irregular edge contrast boundaries compared to natural rendering.
     */
    private double calculateTextRegionSpliceVariance(BufferedImage img, int startY, int bandH, int width) {
        double totalEdgeDivergence = 0.0;
        int sampledPairs = 0;

        int step = Math.max(1, bandH / 8);
        int colStep = Math.max(1, width / 30);

        for (int y = startY + 2; y < startY + bandH - 2; y += step) {
            for (int x = 2; x < width - 2; x += colStep) {
                int p1 = img.getRGB(x, y) & 0xFF;
                int p2 = img.getRGB(x + 1, y) & 0xFF;
                int pAbove = img.getRGB(x, y - 1) & 0xFF;

                double horizDiff = Math.abs(p1 - p2);
                double vertDiff = Math.abs(p1 - pAbove);

                // Severe abrupt jump characteristic of cut-and-paste typography
                if (horizDiff > 140 && vertDiff < 20) {
                    totalEdgeDivergence += 1.0;
                }
                sampledPairs++;
            }
        }

        if (sampledPairs == 0) return 0.0;
        double ratio = totalEdgeDivergence / sampledPairs;
        return Math.min(1.0, ratio * 3.5);
    }

    /**
     * Scans raw bytes for common broadcast chyron text tokens.
     */
    private String scanAsciiChyronKeywords(byte[] data) {
        String raw = new String(data, 0, Math.min(data.length, 32768), StandardCharsets.ISO_8859_1);
        String upper = raw.toUpperCase(Locale.ROOT);

        String[] keywords = {
                "BREAKING NEWS",
                "NEWS ALERT",
                "EXCLUSIVE REPORT",
                "SPECIAL REPORT",
                "LIVE COVERAGE",
                "DEVELOPING STORY",
                "URGENT DISPATCH"
        };

        for (String kw : keywords) {
            int idx = upper.indexOf(kw);
            if (idx != -1) {
                // Extract surrounding sentence/line up to 120 chars
                int end = Math.min(raw.length(), idx + 120);
                String snippet = raw.substring(idx, end).replaceAll("[\\r\\n\\x00-\\x1F]", " ").trim();
                return snippet;
            }
        }
        return null;
    }
}
