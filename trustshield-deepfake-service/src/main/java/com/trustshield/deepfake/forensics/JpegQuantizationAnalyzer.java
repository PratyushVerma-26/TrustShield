package com.trustshield.deepfake.forensics;

import com.trustshield.common.util.HashUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * JPEG Quantization Table (DQT) fingerprinting analyzer.
 *
 * <p>Directly parses raw JPEG byte streams to extract {@code 0xFF 0xDB} (DQT) marker
 * segments. Quantization tables govern lossy discrete cosine transform (DCT) coefficient
 * reduction and provide a unique hardware or software fingerprint.
 *
 * <p>Standard digital cameras utilize camera-specific quantization tables. Image editing
 * suites (such as Photoshop or GIMP) apply distinctive non-camera tables, while synthetic
 * media pipelines frequently employ all-ones (flat) or non-standard quantization curves.
 */
@Component
public class JpegQuantizationAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(JpegQuantizationAnalyzer.class);

    // Standard Adobe Photoshop DQT table fingerprints or signatures
    private static final List<int[]> STANDARD_PHOTOSHOP_LUM = List.of(
            new int[]{6, 4, 4, 6, 9, 11, 12, 16, 4, 5, 5, 6, 8, 10, 12, 12, 4, 5, 5, 6, 10, 12, 14, 19, 6, 6, 8, 12, 14, 17, 24, 27},
            new int[]{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
    );

    public record DqtResult(
            boolean anomalous,
            String fingerprint,
            String detail,
            List<int[]> tables
    ) {}

    /**
     * Parses raw image bytes and inspects 0xFFDB JPEG quantization tables.
     *
     * @param rawBytes image binary data
     * @return DqtResult with tables, fingerprint, and anomaly evaluation
     */
    public DqtResult analyze(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 4) {
            return new DqtResult(false, "NONE", "Image payload too small or empty", List.of());
        }

        // Verify JPEG SOI marker (0xFF 0xD8)
        if ((rawBytes[0] & 0xFF) != 0xFF || (rawBytes[1] & 0xFF) != 0xD8) {
            return new DqtResult(false, "NON_JPEG", "Format is not JPEG; DQT marker inspection bypassed", List.of());
        }

        List<int[]> extractedTables = new ArrayList<>();
        int i = 2;
        int n = rawBytes.length;

        try {
            while (i < n - 1) {
                if ((rawBytes[i] & 0xFF) == 0xFF) {
                    int marker = rawBytes[i + 1] & 0xFF;

                    // Skip fill bytes (0xFF)
                    if (marker == 0xFF) {
                        i++;
                        continue;
                    }

                    // 0xD8 (SOI), 0xD9 (EOI), 0x00 (stuffed byte)
                    if (marker == 0xD8) {
                        i += 2;
                        continue;
                    }
                    if (marker == 0xD9) {
                        break; // End of image
                    }

                    // Markers with length: 0xC0..0xFE (excluding 0x00 and standalone markers)
                    if (i + 3 >= n) {
                        break;
                    }
                    int length = ((rawBytes[i + 2] & 0xFF) << 8) | (rawBytes[i + 3] & 0xFF);

                    if (marker == 0xDB) { // DQT marker
                        int segPos = i + 4;
                        int segEnd = i + 2 + length;

                        while (segPos < segEnd && segPos < n) {
                            int info = rawBytes[segPos] & 0xFF;
                            int precision = (info >> 4) & 0x0F; // 0 = 8-bit, 1 = 16-bit
                            segPos++;

                            int tableSize = 64;
                            if (precision == 0) { // 8-bit table
                                if (segPos + 64 <= n) {
                                    int[] table = new int[64];
                                    for (int k = 0; k < 64; k++) {
                                        table[k] = rawBytes[segPos + k] & 0xFF;
                                    }
                                    extractedTables.add(table);
                                    segPos += 64;
                                } else {
                                    break;
                                }
                            } else { // 16-bit table
                                if (segPos + 128 <= n) {
                                    int[] table = new int[64];
                                    for (int k = 0; k < 64; k++) {
                                        table[k] = ((rawBytes[segPos + 2 * k] & 0xFF) << 8) | (rawBytes[segPos + 2 * k + 1] & 0xFF);
                                    }
                                    extractedTables.add(table);
                                    segPos += 128;
                                } else {
                                    break;
                                }
                            }
                        }
                    }

                    i += 2 + length;
                } else {
                    i++;
                }
            }
        } catch (Exception e) {
            log.debug("Error while scanning JPEG segments: {}", e.getMessage());
        }

        if (extractedTables.isEmpty()) {
            return new DqtResult(false, "NO_DQT_FOUND", "No 0xFFDB quantization tables detected in JPEG stream", List.of());
        }

        // Build fingerprint
        StringBuilder sb = new StringBuilder();
        for (int t = 0; t < extractedTables.size(); t++) {
            sb.append("T").append(t).append(":");
            sb.append(Arrays.toString(extractedTables.get(t)));
            sb.append(";");
        }
        String fingerprint = HashUtils.sha256Hex(sb.toString()).substring(0, 16);

        // Anomaly checks
        boolean isAnomalous = false;
        StringBuilder anomalyDetail = new StringBuilder();

        for (int[] tbl : extractedTables) {
            // Check 1: All-ones or flat synthetic tables (common in uncalibrated synthetic image generation)
            boolean allOnes = Arrays.stream(tbl).allMatch(v -> v == 1);
            boolean allFlat = Arrays.stream(tbl).distinct().count() <= 1;

            if (allOnes || allFlat) {
                isAnomalous = true;
                anomalyDetail.append("Uniform/flat quantization table detected (characteristic of synthetic media generation). ");
            }

            // Check 2: Extreme values
            int maxVal = Arrays.stream(tbl).max().orElse(0);
            int minVal = Arrays.stream(tbl).min().orElse(0);
            if (minVal == 0) {
                isAnomalous = true;
                anomalyDetail.append("Illegal zero-value coefficient in quantization table. ");
            }
        }

        String detail = isAnomalous
                ? anomalyDetail.toString().trim()
                : String.format("Standard quantization tables verified (%d tables extracted, hash: %s)", extractedTables.size(), fingerprint);

        return new DqtResult(isAnomalous, fingerprint, detail, extractedTables);
    }
}
