package com.trustshield.fusion.engine.rules;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CoverageUnknownRuleTest {

    private CoverageUnknownRule rule;

    @BeforeEach
    void setUp() {
        rule = new CoverageUnknownRule();
    }

    @Test
    @DisplayName("R3 fires when any module returns UNKNOWN threat level")
    void firesOnUnknownThreatLevel() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.FAKENEWS,
                0,
                ThreatLevel.UNKNOWN,
                "NO_SOURCES_CONSULTED",
                "Unindexed claim and external API unreachable",
                List.of(),
                10L,
                Instant.now(),
                true
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.FAKENEWS, v1);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
        assertEquals("R3", result.ruleId());
        assertEquals(ThreatLevel.UNKNOWN, result.resultingLevel());
    }

    @Test
    @DisplayName("R3 fires when any module operates in degraded mode")
    void firesOnDegradedVerdict() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                0,
                ThreatLevel.UNKNOWN,
                "IMAGE_RECOMPRESSED",
                "Severe recompression destroyed fine sensor noise",
                List.of(),
                8L,
                Instant.now(),
                true // degraded
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.DEEPFAKE, v1);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
    }

    @Test
    @DisplayName("R3 fires when request contains empty modular contributions")
    void firesOnEmptyContributions() {
        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(), true);
        FusionRuleResult result = rule.evaluate(request, Map.of());

        assertTrue(result.fired());
        assertEquals(ThreatLevel.UNKNOWN, result.resultingLevel());
    }

    @Test
    @DisplayName("R3 does not fire when all modules are conclusive and non-degraded")
    void doesNotFireWhenFullyConclusive() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.PHISHING,
                10,
                ThreatLevel.SAFE,
                "LEXICAL_CLEAN",
                "Lexical features indicate legitimate domain",
                List.of(),
                3L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.PHISHING, v1);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertFalse(result.fired());
    }
}
