package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class C2paManifestDetectorTest {

    private C2paManifestDetector detector;

    @BeforeEach
    void setUp() {
        detector = new C2paManifestDetector();
    }

    @Test
    @DisplayName("returns false when no C2PA signatures exist")
    void returnsFalseWhenAbsent() {
        byte[] payload = "plain-image-payload-without-manifest-markers".getBytes(StandardCharsets.US_ASCII);
        C2paManifestDetector.C2paResult result = detector.detect(payload);

        assertThat(result.detected()).isFalse();
        assertThat(result.detail()).contains("No C2PA provenance manifest detected");
    }

    @Test
    @DisplayName("detects presence of c2pa box marker")
    void detectsC2paMarker() {
        byte[] payload = "prefix-header-bytes-c2pa-box-data-suffix".getBytes(StandardCharsets.US_ASCII);
        C2paManifestDetector.C2paResult result = detector.detect(payload);

        assertThat(result.detected()).isTrue();
        assertThat(result.detail()).contains("C2PA / JUMBF provenance manifest detected");
    }

    @Test
    @DisplayName("detects presence of jumb box marker")
    void detectsJumbMarker() {
        byte[] payload = "prefix-header-bytes-jumb-box-data-suffix".getBytes(StandardCharsets.US_ASCII);
        C2paManifestDetector.C2paResult result = detector.detect(payload);

        assertThat(result.detected()).isTrue();
    }
}
