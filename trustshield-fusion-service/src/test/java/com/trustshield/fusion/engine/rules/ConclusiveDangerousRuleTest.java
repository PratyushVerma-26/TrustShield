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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConclusiveDangerousRuleTest {

    private ConclusiveDangerousRule rule;

    @BeforeEach
    void setUp() {
        rule = new ConclusiveDangerousRule();
    }

    @Test
    @DisplayName("R1 fires when any single module returns conclusive DANGEROUS")
    void firesOnConclusiveDangerous() {
        ModuleVerdict phishingDangerous = new ModuleVerdict(
                ModuleType.PHISHING,
                92,
                ThreatLevel.DANGEROUS,
                "PHISHING_HEURISTIC_HIT",
                "High-confidence phishing domain detected",
                List.of(),
                5L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(phishingDangerous), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.PHISHING, phishingDangerous);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
        assertEquals("R1", result.ruleId());
        assertEquals(ThreatLevel.DANGEROUS, result.resultingLevel());
    }

    @Test
    @DisplayName("R1 does not fire if DANGEROUS verdict is degraded/inconclusive")
    void doesNotFireWhenDegraded() {
        ModuleVerdict degradedDangerous = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                80,
                ThreatLevel.DANGEROUS,
                "INCONCLUSIVE_RECOMPRESSION",
                "Heuristic hit but degraded",
                List.of(),
                5L,
                Instant.now(),
                true // degraded
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(degradedDangerous), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.DEEPFAKE, degradedDangerous);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertFalse(result.fired());
        assertNull(result.resultingLevel());
    }

    @Test
    @DisplayName("R1 does not fire on SUSPICIOUS, LOW, or SAFE verdicts")
    void doesNotFireOnNonDangerous() {
        ModuleVerdict suspicious = new ModuleVerdict(
                ModuleType.FAKENEWS,
                45,
                ThreatLevel.SUSPICIOUS,
                "SENSATIONALIST_STYLE",
                "Sensational text",
                List.of(),
                5L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(suspicious), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(ModuleType.FAKENEWS, suspicious);

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertFalse(result.fired());
    }
}
