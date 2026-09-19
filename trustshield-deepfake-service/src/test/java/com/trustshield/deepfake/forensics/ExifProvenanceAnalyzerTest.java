package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class ExifProvenanceAnalyzerTest {

    private ExifProvenanceAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new ExifProvenanceAnalyzer();
    }

    @Test
    @DisplayName("handles empty or tiny payloads cleanly")
    void handlesTinyPayload() {
        ExifProvenanceAnalyzer.ExifResult result = analyzer.analyze(new byte[2]);
        assertThat(result.hasExif()).isFalse();
        assertThat(result.metadataInconsistent()).isFalse();
    }

    @Test
    @DisplayName("reports absence of EXIF on raw unannotated JPEG")
    void reportsAbsenceOfExif() {
        // Minimal valid JPEG without APP1 (EXIF) segment
        byte[] minimalJpeg = new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xD9};
        ExifProvenanceAnalyzer.ExifResult result = analyzer.analyze(minimalJpeg);

        assertThat(result.hasExif()).isFalse();
        assertThat(result.cameraModel()).isNull();
        assertThat(result.detail()).contains("No EXIF metadata present");
    }
}
