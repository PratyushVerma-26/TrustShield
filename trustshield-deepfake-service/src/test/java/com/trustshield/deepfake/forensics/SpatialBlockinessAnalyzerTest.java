package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;

import static org.assertj.core.api.Assertions.assertThat;

class SpatialBlockinessAnalyzerTest {

    private SpatialBlockinessAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new SpatialBlockinessAnalyzer();
    }

    @Test
    @DisplayName("smooth gradient image has spatial blockiness ratio near 1.0")
    void smoothGradientProducesRatioNearOne() {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 64; y++) {
            for (int x = 0; x < 64; x++) {
                int c = (x + y) * 2;
                int rgb = (c << 16) | (c << 8) | c;
                img.setRGB(x, y, rgb);
            }
        }

        SpatialBlockinessAnalyzer.BlockinessResult result = analyzer.analyze(img, 1.5);

        assertThat(result.periodicityScore()).isBetween(0.8, 1.2);
        assertThat(result.anomalous()).isFalse();
        assertThat(result.detail()).contains("Spatial 8x8 blockiness proxy ratio");
    }

    @Test
    @DisplayName("pronounced 8x8 block discontinuities elevate the periodicity ratio")
    void blockArtifactsElevatePeriodicityRatio() {
        BufferedImage img = new BufferedImage(64, 64, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < 64; y++) {
            int blockY = y / 8;
            for (int x = 0; x < 64; x++) {
                int blockX = x / 8;
                // Flat color inside block, sharp step between blocks
                int val = ((blockX + blockY) % 2 == 0) ? 50 : 200;
                int rgb = (val << 16) | (val << 8) | val;
                img.setRGB(x, y, rgb);
            }
        }

        SpatialBlockinessAnalyzer.BlockinessResult result = analyzer.analyze(img, 1.2);

        assertThat(result.periodicityScore()).isGreaterThan(1.5);
        assertThat(result.anomalous()).isTrue();
    }
}
