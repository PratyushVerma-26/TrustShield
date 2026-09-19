package com.trustshield.fakenews.multimodal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NewsChyronAnalyzerTest {

    private NewsChyronAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new NewsChyronAnalyzer(0.65);
    }

    @Test
    @DisplayName("Empty or null bytes returns clean analysis")
    void handlesEmptyBytesCleanly() {
        var result = analyzer.analyze(new byte[0], "empty.jpg");
        assertFalse(result.chyronDetected());
        assertFalse(result.splicedOrManipulated());
        assertEquals("NONE", result.bannerType());
    }

    @Test
    @DisplayName("Detects ASCII chyron keywords in news payload bytes")
    void detectsAsciiBreakingNewsChyron() {
        byte[] payload = "BREAKING NEWS: Massive blackout hits major metropolitan district".getBytes(StandardCharsets.ISO_8859_1);
        var result = analyzer.analyze(payload, "news_snippet.bin");

        assertTrue(result.chyronDetected());
        assertNotNull(result.extractedBannerText());
        assertTrue(result.extractedBannerText().contains("BREAKING NEWS"));
    }

    @Test
    @DisplayName("Detects red lower-third breaking news banner in raster image")
    void detectsRasterBreakingNewsRedBanner() throws Exception {
        int width = 300;
        int height = 200;
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();

        // Fill background with neutral gray
        g.setColor(new Color(120, 120, 120));
        g.fillRect(0, 0, width, height);

        // Draw red breaking news chyron across the bottom 25%
        g.setColor(new Color(200, 20, 20));
        g.fillRect(0, 150, width, 50);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        byte[] imageBytes = baos.toByteArray();

        var result = analyzer.analyze(imageBytes, "broadcast_capture.png");

        assertTrue(result.chyronDetected());
        assertEquals("BREAKING_NEWS_RED_BANNER", result.bannerType());
    }
}
