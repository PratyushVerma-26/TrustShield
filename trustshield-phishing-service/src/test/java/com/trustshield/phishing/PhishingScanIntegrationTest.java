package com.trustshield.phishing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests over the HTTP surface.
 *
 * <p>The most valuable thing these do is start the whole application context. A
 * missing bean, a malformed {@code application.yml}, a JPA mapping the dialect
 * rejects, or a model file that fails its startup validation all surface here as
 * a test failure rather than five minutes before a demo.
 *
 * <p>The scoring assertions are deliberately <em>relative</em>, not absolute. The
 * bundled model is an untrained bootstrap, so asserting "this URL scores 87" would
 * pin the test to arbitrary hand-picked weights and would break the moment a real
 * model is trained. Asserting that a look-alike banking domain on an abused TLD
 * scores higher than google.com is a property that must hold for any competent
 * model, so it stays meaningful after retraining.
 */
@SpringBootTest(properties = {
        // Pinned off so the suite behaves identically on a machine that happens to
        // have API keys exported. Tests must not make outbound network calls.
        "trustshield.phishing.reputation.google-safe-browsing.enabled=false",
        "trustshield.phishing.reputation.virustotal.enabled=false"
})
@AutoConfigureMockMvc
class PhishingScanIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode scan(String url) throws Exception {
        String body = MAPPER.writeValueAsString(java.util.Map.of("url", url));
        String response = mockMvc.perform(post("/api/v1/phishing/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return MAPPER.readTree(response);
    }

    @Test
    @DisplayName("context starts and a scan returns a complete verdict")
    void scanReturnsCompleteVerdict() throws Exception {
        JsonNode result = scan("http://sbi-secure-login.verify-account.xyz/netbanking/update.php");

        JsonNode verdict = result.path("verdict");
        assertEquals("PHISHING", verdict.path("module").asText());
        assertTrue(verdict.path("riskScore").isInt(), "riskScore must be present");
        assertTrue(verdict.path("threatLevel").isTextual(), "threatLevel must be derived");
        assertTrue(verdict.path("explanation").asText().length() > 10,
                "A verdict without an explanation is not evidence");
        assertTrue(verdict.path("signals").isArray() && !verdict.path("signals").isEmpty(),
                "Every verdict must carry the signals that produced it");
        assertTrue(result.path("scanId").isNumber(), "The scan must be persisted");
    }

    @Test
    @DisplayName("a look-alike banking domain outranks a well-known safe site")
    void relativeOrderingHolds() throws Exception {
        int phishing = scan("http://sbi-secure-login.verify-account.xyz/netbanking/login.php")
                .path("verdict").path("riskScore").asInt();
        int benign = scan("https://www.google.com/")
                .path("verdict").path("riskScore").asInt();

        assertTrue(phishing > benign,
                "Expected the look-alike domain to score above google.com, but got "
                        + phishing + " vs " + benign
                        + ". If this fails, the model weights or the feature signs are wrong.");
    }

    @Test
    @DisplayName("external sources are absent by default and the verdict says so")
    void degradesGracefullyWithoutApiKeys() throws Exception {
        JsonNode result = scan("https://example.com/");

        // With no keys configured, both sources should report themselves as not
        // consulted. Silence must never be reported as a clean bill of health.
        JsonNode reputation = result.path("reputation");
        assertTrue(reputation.isArray() && !reputation.isEmpty(),
                "The response must state which sources were consulted");
        for (JsonNode source : reputation) {
            assertFalse(source.path("available").asBoolean(),
                    "No API keys are configured in tests, so no source can be available");
            assertFalse(source.path("flagged").asBoolean(),
                    "An unavailable source must not be recorded as flagging anything");
        }
    }

    @Test
    @DisplayName("feature attribution is returned with the score")
    void returnsExplainability() throws Exception {
        JsonNode features = scan("http://192.168.1.1/account/login.php").path("topFeatures");
        assertTrue(features.isArray() && !features.isEmpty(),
                "The score must come with per-feature attribution");
        JsonNode first = features.get(0);
        assertTrue(first.path("feature").isTextual());
        assertTrue(first.path("description").isTextual());
        assertTrue(first.path("logitDelta").isNumber());
    }

    @Test
    @DisplayName("a blank URL is rejected rather than scored")
    void rejectsBlankUrl() throws Exception {
        mockMvc.perform(post("/api/v1/phishing/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"url\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    @Test
    @DisplayName("the model card discloses whether the weights were trained")
    void modelCardDisclosesProvenance() throws Exception {
        mockMvc.perform(get("/api/v1/phishing/model"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.featureCount").value(26))
                .andExpect(jsonPath("$.provenance").exists())
                .andExpect(jsonPath("$.trained").exists());
    }

    @Test
    @DisplayName("scans appear in history")
    void historyRecordsScans() throws Exception {
        scan("http://free-gift-card.tk/claim");

        mockMvc.perform(get("/api/v1/phishing/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].url").exists())
                .andExpect(jsonPath("$[0].riskScore").exists());
    }
}
