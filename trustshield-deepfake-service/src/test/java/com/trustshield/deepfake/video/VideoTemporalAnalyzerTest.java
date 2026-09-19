package com.trustshield.deepfake.video;

import com.trustshield.deepfake.forensics.NoiseResidualAnalyzer;
import com.trustshield.deepfake.forensics.SpatialBlockinessAnalyzer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class VideoTemporalAnalyzerTest {

    private final VideoTemporalAnalyzer analyzer = new VideoTemporalAnalyzer(
            new NoiseResidualAnalyzer(),
            new SpatialBlockinessAnalyzer()
    );

    @Test
    @DisplayName("evaluates smooth video frames with high consistency and minimal jitter")
    void evaluatesSmoothFrames() {
        BufferedImage f1 = createSolidImage(200, 200, new Color(50, 50, 50));
        BufferedImage f2 = createSolidImage(200, 200, new Color(52, 52, 52));
        BufferedImage f3 = createSolidImage(200, 200, new Color(54, 54, 54));

        var result = analyzer.analyzeFrames(List.of(f1, f2, f3), "CAM_ORIGINAL");

        assertThat(result.videoAnalyzed()).isTrue();
        assertThat(result.frameCount()).isEqualTo(3);
        assertThat(result.temporalJitterScore()).isLessThan(0.30);
        assertThat(result.frameConsistencyScore()).isGreaterThan(0.70);
    }

    @Test
    @DisplayName("detects temporal jitter between frames with alternating noise spikes")
    void detectsTemporalJitter() {
        BufferedImage f1 = createSolidImage(200, 200, new Color(50, 50, 50));
        BufferedImage f2 = createNoisyImage(200, 200);
        BufferedImage f3 = createSolidImage(200, 200, new Color(50, 50, 50));

        var result = analyzer.analyzeFrames(List.of(f1, f2, f3), "DEEPFACELAB");

        assertThat(result.videoAnalyzed()).isTrue();
        assertThat(result.temporalJitterScore()).isGreaterThan(0.35);
        assertThat(result.containerSoftware()).isEqualTo("DEEPFACELAB");
    }

    private BufferedImage createSolidImage(int w, int h, Color c) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(c);
        g.fillRect(0, 0, w, h);
        g.dispose();
        return img;
    }

    private BufferedImage createNoisyImage(int w, int h) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < h; y++) {
            for (int x = 0; x < w; x++) {
                int noise = (int) (Math.random() * 200);
                img.setRGB(x, y, new Color(noise, noise, noise).getRGB());
            }
        }
        return img;
    }
}
