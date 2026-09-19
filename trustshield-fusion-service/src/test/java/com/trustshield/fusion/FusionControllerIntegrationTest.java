package com.trustshield.fusion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class FusionControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/v1/fusion/evaluate fuses multi-vector threats and elevates via R1")
    void evaluateIncidentFusesMultiVectorThreats() throws Exception {
        ModuleVerdict phishing = new ModuleVerdict(
                ModuleType.PHISHING,
                95,
                ThreatLevel.DANGEROUS,
                "VIRUSTOTAL_CONFIRMED_MALICIOUS",
                "Flagged by 12 threat intelligence engines",
                List.of(),
                4L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(
                IncidentId.generate(),
                List.of(phishing),
                true
        );

        String json = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/v1/fusion/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.incidentId").exists())
                .andExpect(jsonPath("$.aggregateVerdict.threatLevel").value("DANGEROUS"))
                .andExpect(jsonPath("$.aggregateVerdict.riskScore").value(95))
                .andExpect(jsonPath("$.firedRules[?(@.ruleId == 'R1')].fired").value(true))
                .andExpect(jsonPath("$.ledgerVerified").value(true));
    }

    @Test
    @DisplayName("GET /api/v1/fusion/rules returns all five canonical fusion rules")
    void rulesEndpointReturnsAllActiveRules() throws Exception {
        mockMvc.perform(get("/api/v1/fusion/rules"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(5))
                .andExpect(jsonPath("$[0].ruleId").value("R1"))
                .andExpect(jsonPath("$[1].ruleId").value("R2"))
                .andExpect(jsonPath("$[2].ruleId").value("R3"))
                .andExpect(jsonPath("$[3].ruleId").value("R4"))
                .andExpect(jsonPath("$[4].ruleId").value("R5"));
    }

    @Test
    @DisplayName("GET /api/v1/fusion/history, stats, and info endpoints return valid data")
    void historyStatsAndInfoEndpointsReturnValidData() throws Exception {
        mockMvc.perform(get("/api/v1/fusion/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());

        mockMvc.perform(get("/api/v1/fusion/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalIncidentsEvaluated").isNumber())
                .andExpect(jsonPath("$.activeRulesCount").value(5));

        mockMvc.perform(get("/api/v1/fusion/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("trustshield-fusion-service"))
                .andExpect(jsonPath("$.port").value(8088))
                .andExpect(jsonPath("$.rules").isArray());
    }

    @Test
    @DisplayName("Incident alias route /api/v1/incident/evaluate operates identically")
    void incidentAliasRouteWorksIdentically() throws Exception {
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(), true);
        String json = objectMapper.writeValueAsString(request);

        mockMvc.perform(post("/api/v1/incident/evaluate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.aggregateVerdict.threatLevel").value("UNKNOWN"));
    }
}
