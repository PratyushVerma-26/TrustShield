package com.trustshield.deepfake.forensics;

import com.trustshield.common.dto.DeepfakeScanResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the core system invariant:
 * A recompressed image has had its forensic traces destroyed, so the honest
 * verdict must be UNKNOWN (score 0, degraded=true), never a false claim of safety.
 */
class RecompressionFailureTest {

    private ImageForensicOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        ElaAnalyzer ela = new ElaAnalyzer();
        JpegQuantizationAnalyzer dqt = new JpegQuantizationAnalyzer();
        SpatialBlockinessAnalyzer blockiness = new SpatialBlockinessAnalyzer();
        NoiseResidualAnalyzer noise = new NoiseResidualAnalyzer();
        ExifProvenanceAnalyzer exif = new ExifProvenanceAnalyzer();
        C2paManifestDetector c2pa = new C2paManifestDetector();
        RecompressionDetector recompression = new RecompressionDetector();

        orchestrator = new ImageForensicOrchestrator(
                ela, dqt, blockiness, noise, exif, c2pa, recompression
        );

        ReflectionTestUtils.setField(orchestrator, "elaQuality", 0.90f);
        ReflectionTestUtils.setField(orchestrator, "elaVarianceThreshold", 120.0);
        ReflectionTestUtils.setField(orchestrator, "blockinessThreshold", 0.70);
        ReflectionTestUtils.setField(orchestrator, "noiseVarianceThreshold", 85.0);
        ReflectionTestUtils.setField(orchestrator, "noiseHyperSmoothThreshold", 1.5);
    }

    @Test
    @DisplayName("recompressed media from messaging platform (WHATSAPP_ATTACHMENT) returns UNKNOWN, score 0, and degraded=true")
    void recompressedSocialMediaReturnsUnknown() throws Exception {
        // Create an image and encode it as plain JPEG without EXIF
        BufferedImage img = new BufferedImage(400, 300, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(100, 150, 200));
        g.fillRect(0, 0, 400, 300);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "jpg", baos);
        byte[] rawBytes = baos.toByteArray();

        DeepfakeScanResponse response = orchestrator.orchestrate(
                IncidentId.generate(),
                rawBytes,
                "whatsapp_photo.jpg",
                "image/jpeg",
                "WHATSAPP_ATTACHMENT"
        );

        // Assert invariant: must NOT return SAFE or a clean bill of health
        assertThat(response.verdict().threatLevel()).isEqualTo(ThreatLevel.UNKNOWN);
        assertThat(response.verdict().riskScore()).isEqualTo(0);
        assertThat(response.verdict().degraded()).isTrue();
        assertThat(response.verdict().verdict()).isEqualTo("IMAGE_RECOMPRESSED");
        assertThat(response.verdict().explanation()).contains("Forensic traces destroyed by lossy recompression");
        assertThat(response.forensicSignals().recompressionDetected()).isTrue();
    }

    @Test
    @DisplayName("downscaled low-resolution thumbnail without EXIF returns UNKNOWN")
    void downscaledThumbnailReturnsUnknown() throws Exception {
        BufferedImage tiny = new BufferedImage(120, 120, BufferedImage.TYPE_INT_RGB);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(tiny, "jpg", baos);
        byte[] rawBytes = baos.toByteArray();

        DeepfakeScanResponse response = orchestrator.orchestrate(
                IncidentId.generate(),
                rawBytes,
                "thumb.jpg",
                "image/jpeg",
                "WEB_PREVIEW"
        );

        assertThat(response.verdict().threatLevel()).isEqualTo(ThreatLevel.UNKNOWN);
        assertThat(response.verdict().riskScore()).isEqualTo(0);
        assertThat(response.verdict().degraded()).isTrue();
        assertThat(response.verdict().verdict()).isEqualTo("IMAGE_RECOMPRESSED");
    }
}
