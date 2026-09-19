package com.trustshield.common.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.trustshield.common.util.HashUtils;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContractsTest {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void incidentIdCreationAndValidation() {
        IncidentId id = IncidentId.of("inc-12345");
        assertThat(id.value()).isEqualTo("inc-12345");
        assertThat(id.toString()).isEqualTo("inc-12345");

        IncidentId generated = IncidentId.generate();
        assertThat(generated.value()).startsWith("inc-");

        assertThatThrownBy(() -> new IncidentId(null))
                .isInstanceOf(NullPointerException.class);

        assertThatThrownBy(() -> new IncidentId("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void incidentIdJsonRoundTrip() throws Exception {
        IncidentId id = IncidentId.of("inc-abc-789");
        String json = mapper.writeValueAsString(id);
        assertThat(json).isEqualTo("\"inc-abc-789\"");

        IncidentId deserialized = mapper.readValue(json, IncidentId.class);
        assertThat(deserialized).isEqualTo(id);
    }

    @Test
    void deepfakeContractsRoundTrip() throws Exception {
        IncidentId incId = IncidentId.of("inc-df-01");
        DeepfakeScanRequest req = new DeepfakeScanRequest(incId, "dGVzdA==", "photo.jpg", "image/jpeg", "WHATSAPP");
        assertThat(req.incidentId()).isEqualTo(incId);

        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.DEEPFAKE,
                82,
                "MANIPULATION_SUSPECTED",
                "High ELA variance and anomalous quantization tables",
                List.of(ThreatSignal.triggered("ELA_VARIANCE", "High local variance", 40, "ELA_FORENSICS")),
                120L
        );

        DeepfakeScanResponse.ImageMetadata meta = new DeepfakeScanResponse.ImageMetadata(
                "photo.jpg", "JPEG", 1920, 1080, 245000L, true, "CameraX", "Editor 1.0", false
        );
        DeepfakeScanResponse.ForensicSignals signals = new DeepfakeScanResponse.ForensicSignals(
                45.2, true, "TABLE_CUSTOM", 0.72, 18.4, true, false, false
        );

        DeepfakeScanResponse resp = new DeepfakeScanResponse(incId, verdict, meta, signals);
        String json = mapper.writeValueAsString(resp);
        assertThat(json).contains("MANIPULATION_SUSPECTED");

        DeepfakeScanResponse read = mapper.readValue(json, DeepfakeScanResponse.class);
        assertThat(read.incidentId()).isEqualTo(incId);
        assertThat(read.verdict().riskScore()).isEqualTo(82);
        assertThat(read.forensicSignals().quantisationTableAnomalous()).isTrue();
    }

    @Test
    void misinformationContractsRoundTrip() throws Exception {
        IncidentId incId = IncidentId.of("inc-fn-01");
        ClaimCheckRequest req = new ClaimCheckRequest(incId, "Breaking: Free recharge scheme announced", "SMS");
        assertThat(req.incidentId()).isEqualTo(incId);

        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.FAKENEWS,
                70,
                "MISINFORMATION_SUSPECTED",
                "Resembles previously debunked viral forward",
                List.of(ThreatSignal.triggered("SIMHASH_DEBUNK_MATCH", "Matched PIB fact check", 50, "DEBUNK_CORPUS")),
                45L
        );

        ClaimCheckResponse.FactCheckResult fc = ClaimCheckResponse.FactCheckResult.unavailable();
        ClaimCheckResponse.SimHashMatch sh = new ClaimCheckResponse.SimHashMatch(true, "Viral recharge scheme debunked", 0.94, "https://pib.gov.in/factcheck/1");
        ClaimCheckResponse.StyleAnalysis style = new ClaimCheckResponse.StyleAnalysis(0.25, 4, List.of("FREE", "URGENT"), List.of("sources confirm"), 35);

        ClaimCheckResponse resp = new ClaimCheckResponse(incId, req.claimText(), verdict, fc, sh, style);
        String json = mapper.writeValueAsString(resp);
        ClaimCheckResponse read = mapper.readValue(json, ClaimCheckResponse.class);

        assertThat(read.incidentId()).isEqualTo(incId);
        assertThat(read.simHashMatch().matched()).isTrue();
        assertThat(read.styleAnalysis().sensationalPunctuationCount()).isEqualTo(4);
    }

    @Test
    void ledgerContractsRoundTrip() throws Exception {
        IncidentId incId = IncidentId.of("inc-lg-01");
        String payload = "{\"status\":\"DANGEROUS\"}";
        String entryHash = HashUtils.sha256Hex(payload);
        String genesisChain = "0".repeat(64);
        String chainHash = HashUtils.chain(genesisChain, entryHash);

        LedgerEntry entry = new LedgerEntry(
                0L, incId, ModuleType.PHISHING, entryHash, genesisChain, chainHash, payload, Instant.now()
        );

        String json = mapper.writeValueAsString(entry);
        LedgerEntry read = mapper.readValue(json, LedgerEntry.class);
        assertThat(read.sequenceNumber()).isEqualTo(0L);
        assertThat(read.chainHash()).isEqualTo(chainHash);

        LedgerVerifyResponse verifySuccess = LedgerVerifyResponse.success(1L, chainHash, true);
        assertThat(verifySuccess.valid()).isTrue();
        assertThat(verifySuccess.firstCorruptedIndex()).isNull();

        LedgerVerifyResponse verifyFail = LedgerVerifyResponse.corrupted(2L, "Chain hash mismatch", 5L, chainHash);
        assertThat(verifyFail.valid()).isFalse();
        assertThat(verifyFail.firstCorruptedIndex()).isEqualTo(2L);
    }

    @Test
    void fusionContractsRoundTrip() throws Exception {
        IncidentId incId = IncidentId.of("inc-fus-01");
        ModuleVerdict phishingVerdict = ModuleVerdict.of(
                ModuleType.PHISHING, 85, "PHISHING_DETECTED", "Fake domain detected", List.of(), 50L
        );
        ModuleVerdict deepfakeVerdict = ModuleVerdict.of(
                ModuleType.DEEPFAKE, 65, "MANIPULATION_SUSPECTED", "Manipulated media", List.of(), 100L
        );

        IncidentFusionRequest req = new IncidentFusionRequest(incId, List.of(phishingVerdict, deepfakeVerdict), true);
        assertThat(req.verdicts()).hasSize(2);

        ModuleVerdict aggVerdict = ModuleVerdict.of(
                ModuleType.FUSION, 90, "INCIDENT_DANGEROUS", "Critical threat across multiple modalities", List.of(), 12L
        );

        FusionRuleResult r1 = new FusionRuleResult("R1", "Conclusive Dangerous Escalation", "Any conclusive DANGEROUS makes incident DANGEROUS", true, ThreatLevel.DANGEROUS);
        FusionRuleResult r2 = new FusionRuleResult("R2", "Multi-modal Suspicious Escalation", "Two or more SUSPICIOUS across modalities escalate", false, null);

        IncidentFusionResponse resp = new IncidentFusionResponse(
                incId,
                aggVerdict,
                List.of(r1, r2),
                Map.of(ModuleType.PHISHING, phishingVerdict, ModuleType.DEEPFAKE, deepfakeVerdict),
                Map.of(ModuleType.PHISHING, true, ModuleType.DEEPFAKE, true, ModuleType.BREACH, false),
                true,
                false
        );

        String json = mapper.writeValueAsString(resp);
        IncidentFusionResponse read = mapper.readValue(json, IncidentFusionResponse.class);

        assertThat(read.incidentId()).isEqualTo(incId);
        assertThat(read.aggregateVerdict().riskScore()).isEqualTo(90);
        assertThat(read.firedRules()).hasSize(2);
        assertThat(read.firedRules().getFirst().fired()).isTrue();
        assertThat(read.coverageMap()).containsEntry(ModuleType.PHISHING, true);
    }
}
