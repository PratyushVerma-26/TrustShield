package com.trustshield.bot.router;

import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MicroserviceRouterTest {

    private MicroserviceRouter router;

    @BeforeEach
    void setUp() {
        // Point to unreachable ports with 150ms timeout to verify instant offline fallbacks
        router = new MicroserviceRouter(
                "http://localhost:59991",
                "http://localhost:59992",
                "http://localhost:59993",
                "http://localhost:59994",
                "http://localhost:59995",
                "http://localhost:59996",
                150
        );
    }

    @Test
    @DisplayName("scanUrl gracefully degrades to inconclusive UNKNOWN when Phishing Service is offline")
    void testScanUrlOfflineFallback() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = router.scanUrl("https://example-phish.xyz", id);

        assertNotNull(verdict);
        assertEquals(ModuleType.PHISHING, verdict.module());
        assertEquals(ThreatLevel.UNKNOWN, verdict.threatLevel());
        assertEquals(0, verdict.riskScore());
        assertTrue(verdict.verdict().contains("OFFLINE"));
    }

    @Test
    @DisplayName("checkClaim gracefully degrades to inconclusive UNKNOWN when Fake News Service is offline")
    void testCheckClaimOfflineFallback() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = router.checkClaim("Breaking: Virus detected in tap water", null, "TEXT", id);

        assertNotNull(verdict);
        assertEquals(ModuleType.FAKENEWS, verdict.module());
        assertEquals(ThreatLevel.UNKNOWN, verdict.threatLevel());
        assertEquals(0, verdict.riskScore());
    }

    @Test
    @DisplayName("scanMedia gracefully degrades to inconclusive UNKNOWN when Deepfake Service is offline")
    void testScanMediaOfflineFallback() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = router.scanMedia("dGVzdA==", "IMAGE", "test.jpg", id);

        assertNotNull(verdict);
        assertEquals(ModuleType.DEEPFAKE, verdict.module());
        assertEquals(ThreatLevel.UNKNOWN, verdict.threatLevel());
    }

    @Test
    @DisplayName("checkPassword gracefully degrades to inconclusive UNKNOWN when Breach Service is offline")
    void testCheckPasswordOfflineFallback() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = router.checkPassword("p@ssword123", id);

        assertNotNull(verdict);
        assertEquals(ModuleType.BREACH, verdict.module());
        assertEquals(ThreatLevel.UNKNOWN, verdict.threatLevel());
    }

    @Test
    @DisplayName("evaluateFusion performs local fallback aggregation when Fusion Service is offline")
    void testEvaluateFusionOfflineFallback() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict dangerousPhish = ModuleVerdict.of(
                ModuleType.PHISHING,
                88,
                "PHISHING",
                "Flagged URL",
                List.of(),
                5L
        );
        ModuleVerdict suspiciousClaim = ModuleVerdict.of(
                ModuleType.FAKENEWS,
                65,
                "SUSPICIOUS",
                "Sensational headline",
                List.of(),
                10L
        );

        IncidentFusionResponse response = router.evaluateFusion(List.of(dangerousPhish, suspiciousClaim), id);
        assertNotNull(response);
        assertEquals(88, response.aggregateVerdict().riskScore());
        assertEquals(ThreatLevel.DANGEROUS, response.aggregateVerdict().threatLevel());
    }

    @Test
    @DisplayName("appendAuditLedger completes silently without error when Ledger Service is offline")
    void testAppendAuditLedgerOfflineNoException() {
        IncidentId id = IncidentId.generate();
        assertDoesNotThrow(() -> router.appendAuditLedger(id, ModuleType.PHISHING, "TEST_VERDICT"));
    }
}
