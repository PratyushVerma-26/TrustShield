package com.trustshield.deepfake.video;

import com.trustshield.common.dto.DeepfakeScanResponse.VideoTemporalSignals;
import com.trustshield.deepfake.forensics.NoiseResidualAnalyzer;
import com.trustshield.deepfake.forensics.SpatialBlockinessAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Evaluates inter-frame temporal consistency and boundary jitter across video keyframes.
 *
 * <p>In deepfake videos (e.g. FaceSwap, DeepFaceLab, wav2lip), facial regions flicker with
 * high temporal noise disparity across consecutive frames due to per-frame GAN/diffusion
 * generation without temporal discriminator coherence. Natural physical camera footage
 * exhibits a smooth, coherent temporal noise envelope.
 */
@Component
public class VideoTemporalAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(VideoTemporalAnalyzer.class);

    private final NoiseResidualAnalyzer noiseAnalyzer;
    private final SpatialBlockinessAnalyzer blockinessAnalyzer;

    public VideoTemporalAnalyzer(
            NoiseResidualAnalyzer noiseAnalyzer,
            SpatialBlockinessAnalyzer blockinessAnalyzer
    ) {
        this.noiseAnalyzer = noiseAnalyzer;
        this.blockinessAnalyzer = blockinessAnalyzer;
    }

    /**
     * Evaluates temporal consistency from a sequence of decoded keyframes.
     */
    public VideoTemporalSignals analyzeFrames(List<BufferedImage> frames, String containerSoftware) {
        if (frames == null || frames.isEmpty()) {
            return VideoTemporalSignals.none();
        }

        if (frames.size() == 1) {
            return new VideoTemporalSignals(true, 1, 0.05, 0.95, containerSoftware);
        }

        double totalJitter = 0.0;
        double prevNoiseVariance = -1.0;
        int pairCount = 0;

        for (BufferedImage frame : frames) {
            if (frame == null) continue;
            var noiseResult = noiseAnalyzer.analyze(frame, 85.0, 1.5);
            double currentNoiseVariance = noiseResult.variance();

            if (prevNoiseVariance >= 0.0) {
                // High noise variance divergence between consecutive frames reveals temporal flickering
                double varianceDiff = Math.abs(currentNoiseVariance - prevNoiseVariance);
                double normalizedJitter = Math.min(1.0, varianceDiff / 60.0);
                totalJitter += normalizedJitter;
                pairCount++;
            }
            prevNoiseVariance = currentNoiseVariance;
        }

        double avgJitter = pairCount > 0 ? (totalJitter / pairCount) : 0.0;
        avgJitter = Math.max(0.0, Math.min(1.0, avgJitter));
        double consistency = Math.max(0.0, Math.min(1.0, 1.0 - avgJitter));

        return new VideoTemporalSignals(
                true,
                frames.size(),
                round2(avgJitter),
                round2(consistency),
                containerSoftware
        );
    }

    /**
     * Attempts to extract keyframes from raw video bytes (e.g. scanning for embedded JPEG/JFIF frames
     * or sampling byte slices) and evaluates temporal consistency.
     */
    public VideoTemporalSignals analyzeVideoBytes(byte[] videoBytes, String containerSoftware) {
        if (videoBytes == null || videoBytes.length < 100) {
            return VideoTemporalSignals.none();
        }

        List<BufferedImage> extractedFrames = extractEmbeddedJpegs(videoBytes, 6);

        if (!extractedFrames.isEmpty()) {
            return analyzeFrames(extractedFrames, containerSoftware);
        }

        // Fallback: Segment the video stream into 4 temporal chunks and evaluate byte-entropy variance
        double chunkVarianceJitter = evaluateByteStreamTemporalVariance(videoBytes);
        double consistency = Math.max(0.0, Math.min(1.0, 1.0 - chunkVarianceJitter));

        return new VideoTemporalSignals(
                true,
                4,
                round2(chunkVarianceJitter),
                round2(consistency),
                containerSoftware
        );
    }

    private static final int MAX_FRAME_SEARCH_WINDOW = 4 * 1024 * 1024; // 4 MB maximum search window per keyframe

    /**
     * Extracts embedded JPEG frame sequences (0xFF 0xD8 ... 0xFF 0xD9) often found in Motion-JPEG,
     * embedded thumbnails, or keyframe packets in linear O(N) time with bounded memory.
     */
    private List<BufferedImage> extractEmbeddedJpegs(byte[] bytes, int maxFrames) {
        List<BufferedImage> frames = new ArrayList<>();
        int i = 0;
        while (i < bytes.length - 4 && frames.size() < maxFrames) {
            if ((bytes[i] & 0xFF) == 0xFF && (bytes[i + 1] & 0xFF) == 0xD8 && (bytes[i + 2] & 0xFF) == 0xFF) {
                // Found JPEG start marker
                int start = i;
                int end = -1;
                int searchLimit = Math.min(bytes.length - 1, start + MAX_FRAME_SEARCH_WINDOW);
                for (int j = start + 2; j < searchLimit; j++) {
                    if ((bytes[j] & 0xFF) == 0xFF && (bytes[j + 1] & 0xFF) == 0xD9) {
                        end = j + 2;
                        break;
                    }
                }
                if (end > start && (end - start) > 1024) {
                    try {
                        byte[] jpegBytes = new byte[end - start];
                        System.arraycopy(bytes, start, jpegBytes, 0, jpegBytes.length);
                        BufferedImage img = ImageIO.read(new ByteArrayInputStream(jpegBytes));
                        if (img != null && img.getWidth() >= 64 && img.getHeight() >= 64) {
                            frames.add(img);
                        }
                    } catch (Exception ignored) {}
                    i = end;
                    continue;
                } else {
                    // Advance past marker to guarantee linear O(N) complexity
                    i = start + 2;
                    continue;
                }
            }
            i++;
        }
        return frames;
    }

    private double evaluateByteStreamTemporalVariance(byte[] bytes) {
        int chunkSize = Math.max(1024, bytes.length / 4);
        double[] entropies = new double[4];

        for (int c = 0; c < 4; c++) {
            int start = c * chunkSize;
            int end = Math.min(bytes.length, start + chunkSize);
            entropies[c] = calculateShannonEntropy(bytes, start, end);
        }

        double mean = 0.0;
        for (double e : entropies) mean += e;
        mean /= 4.0;

        double variance = 0.0;
        for (double e : entropies) {
            variance += Math.pow(e - mean, 2);
        }
        variance /= 4.0;

        // Higher entropy fluctuations across chunks correlate with abrupt spliced scene alterations
        return Math.min(1.0, Math.sqrt(variance) / 1.5);
    }

    private double calculateShannonEntropy(byte[] b, int start, int end) {
        int len = end - start;
        if (len <= 0) return 0.0;
        int[] counts = new int[256];
        for (int i = start; i < end; i++) {
            counts[b[i] & 0xFF]++;
        }
        double entropy = 0.0;
        double log2 = Math.log(2.0);
        for (int c : counts) {
            if (c > 0) {
                double p = (double) c / len;
                entropy -= p * (Math.log(p) / log2);
            }
        }
        return entropy;
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }
}
