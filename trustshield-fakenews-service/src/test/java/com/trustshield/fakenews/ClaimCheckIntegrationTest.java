package com.trustshield.fakenews;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.mock.web.MockMultipartFile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ClaimCheckIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("check endpoint identifies debunked viral claim via SimHash near-duplicate match")
    void identifiesDebunkedViralClaim() throws Exception {
        String requestJson = """
                {
                    "claimText": "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world",
                    "context": "WHATSAPP_FORWARD"
                }
                """;

        String rawResponse = mockMvc.perform(post("/api/v1/misinformation/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").exists())
                .andExpect(jsonPath("$.claimText").exists())
                .andExpect(jsonPath("$.verdict.threatLevel").value("DANGEROUS"))
                .andExpect(jsonPath("$.verdict.riskScore").isNumber())
                .andExpect(jsonPath("$.verdict.verdict").value("SIMHASH_NEAR_DUPLICATE_DEBUNKED"))
                .andExpect(jsonPath("$.simHashMatch.matched").value(true))
                .andExpect(jsonPath("$.simHashMatch.similarity").isNumber())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode root = objectMapper.readTree(rawResponse);
        assertThat(root.path("verdict").path("riskScore").asInt()).isGreaterThanOrEqualTo(85);
        assertThat(root.path("simHashMatch").path("similarity").asDouble()).isGreaterThanOrEqualTo(0.82);
    }

    @Test
    @DisplayName("fakenews alias endpoint routes identically to misinformation")
    void fakenewsAliasEndpointWorksIdentically() throws Exception {
        String requestJson = """
                {
                    "claimText": "Government giving free laptops to all students under Prime Minister scheme click link",
                    "context": "SMS"
                }
                """;

        mockMvc.perform(post("/api/v1/fakenews/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.threatLevel").value("DANGEROUS"))
                .andExpect(jsonPath("$.simHashMatch.matched").value(true));
    }

    @Test
    @DisplayName("Unindexed neutral claim returns UNKNOWN when fact check API is unconfigured")
    void unindexedNeutralClaimReturnsUnknown() throws Exception {
        String requestJson = """
                {
                    "claimText": "New municipal library opens next Tuesday in the civic center building.",
                    "context": "COMMUNITY_NOTICE"
                }
                """;

        mockMvc.perform(post("/api/v1/misinformation/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.threatLevel").value("UNKNOWN"))
                .andExpect(jsonPath("$.verdict.riskScore").value(0))
                .andExpect(jsonPath("$.verdict.degraded").value(true))
                .andExpect(jsonPath("$.verdict.verdict").value("NO_SOURCES_CONSULTED"))
                .andExpect(jsonPath("$.simHashMatch.matched").value(false));
    }

    @Test
    @DisplayName("Sensational text alone caps at SUSPICIOUS and never reaches DANGEROUS")
    void sensationalTextCapsAtSuspicious() throws Exception {
        String requestJson = """
                {
                    "claimText": "SHOCKING SECRET EXPOSED! Sources confirm that leaked documents prove shocking hidden agenda! Share now before deleted!!",
                    "context": "FORWARD"
                }
                """;

        String rawResponse = mockMvc.perform(post("/api/v1/misinformation/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.threatLevel").value("SUSPICIOUS"))
                .andExpect(jsonPath("$.simHashMatch.matched").value(false))
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode root = objectMapper.readTree(rawResponse);
        int score = root.path("verdict").path("riskScore").asInt();
        assertThat(score).isLessThanOrEqualTo(55);
    }

    @Test
    @DisplayName("History, stats, claims, and info endpoints return valid data")
    void auxiliaryEndpointsReturnValidData() throws Exception {
        // GET /history
        mockMvc.perform(get("/api/v1/misinformation/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());

        // GET /stats
        mockMvc.perform(get("/api/v1/misinformation/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalChecks").isNumber())
                .andExpect(jsonPath("$.catalogEntryCount").isNumber());

        // GET /claims
        mockMvc.perform(get("/api/v1/misinformation/claims"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(20));

        // GET /info
        mockMvc.perform(get("/api/v1/misinformation/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("trustshield-fakenews-service"))
                .andExpect(jsonPath("$.port").value(8086))
                .andExpect(jsonPath("$.styleCappingInvariant").exists())
                .andExpect(jsonPath("$.modalitiesSupported").isArray());

        // GET /directories
        mockMvc.perform(get("/api/v1/misinformation/directories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bundledDebunkDirectoryCount").value(12))
                .andExpect(jsonPath("$.knownNewsSourceCount").value(35));
    }

    @Test
    @DisplayName("check/file multipart endpoint processes uploaded media payload")
    void checkMediaFileEndpointProcessesMultipartUpload() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "breaking_news_screenshot.png",
                "image/png",
                "BREAKING NEWS: Historic weather phenomenon sweeps country".getBytes()
        );

        mockMvc.perform(multipart("/api/v1/misinformation/check/file")
                        .file(file)
                        .param("claimText", "Historic weather phenomenon sweeps country")
                        .param("context", "TELEVISION_BROADCAST"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").exists())
                .andExpect(jsonPath("$.multimodalExtraction.mediaProcessed").value(true))
                .andExpect(jsonPath("$.multimodalExtraction.mediaType").value("IMAGE"))
                .andExpect(jsonPath("$.multimodalExtraction.chyronDetected").value(true));
    }
}
