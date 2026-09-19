package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

class NoiseResidualAnalyzerTest {

    private NoiseResidualAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new NoiseResidualAnalyzer();
    }

    @Test
    @DisplayName("completely flat image is detected as unnaturally hyper-smooth")
    void flatImageIsHyperSmooth() {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        // All pixels identical (variance of residual is 0.0)
        NoiseResidualAnalyzer.NoiseResidualResult result = analyzer.analyze(img, 85.0, 1.5);

        assertThat(result.hyperSmooth()).isTrue();
        assertThat(result.anomalous()).isTrue();
        assertThat(result.detail()).contains("Unnatural absence of optical sensor noise");
    }

    @Test
    @DisplayName("uniformly distributed random noise across blocks shows consistent residual variance")
    void uniformNoiseIsConsistent() {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        Random rng = new Random(42);
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                int noise = 100 + rng.nextInt(50);
                int rgb = (noise << 16) | (noise << 8) | noise;
                img.setRGB(x, y, rgb);
            }
        }

        NoiseResidualAnalyzer.NoiseResidualResult result = analyzer.analyze(img, 500.0, 1.5);

        assertThat(result.hyperSmooth()).isFalse();
        assertThat(result.variance()).isGreaterThan(0.0);
    }
}
