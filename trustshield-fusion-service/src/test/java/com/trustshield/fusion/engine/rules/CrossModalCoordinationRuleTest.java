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

class CrossModalCoordinationRuleTest {

    private CrossModalCoordinationRule rule;

    @BeforeEach
    void setUp() {
        rule = new CrossModalCoordinationRule();
    }

    @Test
    @DisplayName("R5 fires when Phishing co-occurs with Deepfake and both have elevated risk")
    void firesOnPhishingAndDeepfakeCoOccurrence() {
        ModuleVerdict phishing = new ModuleVerdict(
                ModuleType.PHISHING,
                65,
                ThreatLevel.SUSPICIOUS,
                "SUSPICIOUS_LURE",
                "Brand impersonation in subdomain",
                List.of(),
                4L,
                Instant.now(),
                false
        );

        ModuleVerdict deepfake = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                60,
                ThreatLevel.SUSPICIOUS,
                "SYNTHETIC_VOICE_CADENCE",
                "Synthetic vocoder spectral cutoff detected",
                List.of(),
                15L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(phishing, deepfake), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(
                ModuleType.PHISHING, phishing,
                ModuleType.DEEPFAKE, deepfake
        );

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
        assertEquals("R5", result.ruleId());
        assertEquals(ThreatLevel.DANGEROUS, result.resultingLevel());
    }

    @Test
    @DisplayName("R5 does not fire if Phishing risk is trivial (< 25)")
    void doesNotFireWhenRiskTrivial() {
        ModuleVerdict cleanPhishing = new ModuleVerdict(
                ModuleType.PHISHING,
                10,
                ThreatLevel.SAFE,
                "LEXICAL_CLEAN",
                "Clean",
                List.of(),
                3L,
                Instant.now(),
                false
        );

        ModuleVerdict deepfake = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                55,
                ThreatLevel.SUSPICIOUS,
                "UNNATURAL_SMOOTHNESS",
                "Diffusion residual",
                List.of(),
                12L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(cleanPhishing, deepfake), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(
                ModuleType.PHISHING, cleanPhishing,
                ModuleType.DEEPFAKE, deepfake
        );

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertFalse(result.fired());
    }
}
