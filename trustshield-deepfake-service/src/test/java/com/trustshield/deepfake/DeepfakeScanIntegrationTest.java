package com.trustshield.deepfake;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DeepfakeScanIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("forensic scan endpoint processes base64 payload and returns full forensic response")
    void processesBase64ScanRequest() throws Exception {
        BufferedImage img = new BufferedImage(300, 300, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(60, 90, 120));
        g.fillRect(0, 0, 300, 300);
        g.dispose();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "jpg", baos);
        String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());

        String jsonRequest = """
                {
                    "imageBase64": "%s",
                    "filename": "camera_photo.jpg",
                    "mimeType": "image/jpeg",
                    "context": "WEB_UPLOAD"
                }
                """.formatted(b64);

        String rawResponse = mockMvc.perform(post("/api/v1/deepfake/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonRequest))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        JsonNode root = objectMapper.readTree(rawResponse);

        assertThat(root.has("incidentId")).isTrue();
        assertThat(root.has("verdict")).isTrue();
        assertThat(root.has("metadata")).isTrue();
        assertThat(root.has("forensicSignals")).isTrue();

        JsonNode verdict = root.path("verdict");
        assertThat(verdict.path("module").asText()).isEqualTo("DEEPFAKE");
        assertThat(verdict.path("riskScore").isInt()).isTrue();
        assertThat(verdict.path("threatLevel").isTextual()).isTrue();
        assertThat(verdict.path("explanation").asText()).isNotEmpty();
        assertThat(verdict.path("signals").isArray()).isTrue();

        JsonNode meta = root.path("metadata");
        assertThat(meta.path("width").asInt()).isEqualTo(300);
        assertThat(meta.path("height").asInt()).isEqualTo(300);
        assertThat(meta.path("format").asText()).isEqualTo("JPEG");

        JsonNode signals = root.path("forensicSignals");
        assertThat(signals.path("spatialBlockinessScore").isDouble()).isTrue();
        assertThat(signals.path("elaVariance").isDouble()).isTrue();
    }

    @Test
    @DisplayName("forensics info endpoint discloses the 6 classical signals and transparent caveats")
    void disclosesForensicsInfoAndCaveats() throws Exception {
        mockMvc.perform(get("/api/v1/deepfake/forensics/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.module").value("trustshield-deepfake-service"))
                .andExpect(jsonPath("$.port").value(8085))
                .andExpect(jsonPath("$.signals").isArray())
                .andExpect(jsonPath("$.honestLimitations.recompressionHandling").exists())
                .andExpect(jsonPath("$.honestLimitations.generativeAiCaveat").exists());
    }

    @Test
    @DisplayName("history and stats endpoints reflect scanned images")
    void historyAndStatsReflectScans() throws Exception {
        mockMvc.perform(get("/api/v1/deepfake/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalScans").isNumber());

        mockMvc.perform(get("/api/v1/deepfake/history"))
                .andExpect(status().isOk());
    }
}
