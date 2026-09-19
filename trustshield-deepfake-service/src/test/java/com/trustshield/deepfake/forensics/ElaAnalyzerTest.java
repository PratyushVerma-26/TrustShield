package com.trustshield.deepfake.forensics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import static org.assertj.core.api.Assertions.assertThat;

class ElaAnalyzerTest {

    private ElaAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new ElaAnalyzer();
    }

    @Test
    @DisplayName("uniform image produces low ELA variance")
    void uniformImageProducesLowVariance() {
        BufferedImage img = new BufferedImage(128, 128, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(120, 140, 160));
        g.fillRect(0, 0, 128, 128);
        g.dispose();

        ElaAnalyzer.ElaResult result = analyzer.analyze(img, 0.90f, 120.0);

        assertThat(result.variance()).isLessThan(120.0);
        assertThat(result.anomalous()).isFalse();
        assertThat(result.detail()).contains("Uniform ELA error distribution");
    }

    @Test
    @DisplayName("spliced high-contrast localized element elevates ELA block variance")
    void splicedImageElevatesVariance() {
        BufferedImage img = new BufferedImage(128, 128, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(50, 50, 50));
        g.fillRect(0, 0, 128, 128);

        // Localized high-frequency noisy patch simulating pasted element
        g.setColor(Color.WHITE);
        for (int y = 48; y < 80; y += 2) {
            for (int x = 48; x < 80; x += 2) {
                img.setRGB(x, y, 0xFFFFFF);
                img.setRGB(x + 1, y + 1, 0x000000);
            }
        }
        g.dispose();

        ElaAnalyzer.ElaResult result = analyzer.analyze(img, 0.90f, 5.0);

        assertThat(result.variance()).isGreaterThan(0.0);
    }

    @Test
    @DisplayName("handles tiny images gracefully without throwing")
    void handlesSmallImageGracefully() {
        BufferedImage tiny = new BufferedImage(8, 8, BufferedImage.TYPE_INT_RGB);
        ElaAnalyzer.ElaResult result = analyzer.analyze(tiny, 0.90f, 120.0);

        assertThat(result.anomalous()).isFalse();
        assertThat(result.variance()).isEqualTo(0.0);
    }
}
