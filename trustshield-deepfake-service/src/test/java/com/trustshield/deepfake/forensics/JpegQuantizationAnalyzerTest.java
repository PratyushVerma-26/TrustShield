package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class JpegQuantizationAnalyzerTest {

    private JpegQuantizationAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new JpegQuantizationAnalyzer();
    }

    @Test
    @DisplayName("returns NON_JPEG for non-JPEG binary streams")
    void nonJpegReturnsSafeBypass() {
        byte[] pngHeader = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        JpegQuantizationAnalyzer.DqtResult result = analyzer.analyze(pngHeader);

        assertThat(result.anomalous()).isFalse();
        assertThat(result.fingerprint()).isEqualTo("NON_JPEG");
    }

    @Test
    @DisplayName("extracts DQT segments and detects flat synthetic quantization tables")
    void detectsSyntheticFlatTables() {
        byte[] flatJpeg = createSyntheticJpegWithDqt(new int[][]{
                createFlatTable(1), // All 1s
                createFlatTable(1)
        });

        JpegQuantizationAnalyzer.DqtResult result = analyzer.analyze(flatJpeg);

        assertThat(result.tables()).hasSize(2);
        assertThat(result.anomalous()).isTrue();
        assertThat(result.detail()).contains("Uniform/flat quantization table detected");
        assertThat(result.fingerprint()).isNotBlank();
    }

    @Test
    @DisplayName("extracts normal varying DQT tables without anomaly")
    void normalTablesReportClean() {
        int[] standardLum = new int[]{
                16, 11, 10, 16, 24, 40, 51, 61,
                12, 12, 14, 19, 26, 58, 60, 55,
                14, 13, 16, 24, 40, 57, 69, 56,
                14, 17, 22, 29, 51, 87, 80, 62,
                18, 22, 37, 56, 68, 109, 103, 77,
                24, 35, 55, 64, 81, 104, 113, 92,
                49, 64, 78, 87, 103, 121, 120, 101,
                72, 92, 95, 98, 112, 100, 103, 99
        };

        byte[] jpeg = createSyntheticJpegWithDqt(new int[][]{standardLum});
        JpegQuantizationAnalyzer.DqtResult result = analyzer.analyze(jpeg);

        assertThat(result.tables()).hasSize(1);
        assertThat(result.anomalous()).isFalse();
        assertThat(result.fingerprint()).hasSize(16);
    }

    private int[] createFlatTable(int val) {
        int[] tbl = new int[64];
        Arrays.fill(tbl, val);
        return tbl;
    }

    private byte[] createSyntheticJpegWithDqt(int[][] tables) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0xFF);
        baos.write(0xD8); // SOI

        for (int t = 0; t < tables.length; t++) {
            baos.write(0xFF);
            baos.write(0xDB); // DQT marker
            baos.write(0x00);
            baos.write(67); // Length = 64 + 1 info + 2 length = 67
            baos.write(t & 0x0F); // Precision 0 (8-bit), table ID t
            for (int v : tables[t]) {
                baos.write(v & 0xFF);
            }
        }

        baos.write(0xFF);
        baos.write(0xD9); // EOI
        return baos.toByteArray();
    }
}
