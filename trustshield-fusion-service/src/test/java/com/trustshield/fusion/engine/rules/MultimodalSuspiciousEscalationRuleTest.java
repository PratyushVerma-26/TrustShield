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

class MultimodalSuspiciousEscalationRuleTest {

    private MultimodalSuspiciousEscalationRule rule;

    @BeforeEach
    void setUp() {
        rule = new MultimodalSuspiciousEscalationRule();
    }

    @Test
    @DisplayName("R2 fires when two or more distinct modalities return SUSPICIOUS")
    void firesOnTwoSuspiciousModalities() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.PHISHING,
                52,
                ThreatLevel.SUSPICIOUS,
                "SUSPICIOUS_DOMAIN_ENTROPY",
                "Domain entropy elevated",
                List.of(),
                4L,
                Instant.now(),
                false
        );

        ModuleVerdict v2 = new ModuleVerdict(
                ModuleType.DEEPFAKE,
                48,
                ThreatLevel.SUSPICIOUS,
                "HIGH_PASS_NOISE_ANOMALY",
                "Unusual facial skin smoothness",
                List.of(),
                12L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1, v2), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(
                ModuleType.PHISHING, v1,
                ModuleType.DEEPFAKE, v2
        );

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertTrue(result.fired());
        assertEquals("R2", result.ruleId());
        assertEquals(ThreatLevel.DANGEROUS, result.resultingLevel());
    }

    @Test
    @DisplayName("R2 does not fire on only a single SUSPICIOUS modality")
    void doesNotFireOnSingleSuspicious() {
        ModuleVerdict v1 = new ModuleVerdict(
                ModuleType.PHISHING,
                52,
                ThreatLevel.SUSPICIOUS,
                "SUSPICIOUS_DOMAIN",
                "Slightly unusual domain",
                List.of(),
                4L,
                Instant.now(),
                false
        );

        ModuleVerdict v2 = new ModuleVerdict(
                ModuleType.FAKENEWS,
                15,
                ThreatLevel.SAFE,
                "NO_FACT_CHECK_CONCERNS",
                "Verified safe claim",
                List.of(),
                10L,
                Instant.now(),
                false
        );

        IncidentFusionRequest request = new IncidentFusionRequest(IncidentId.generate(), List.of(v1, v2), true);
        Map<ModuleType, ModuleVerdict> contributions = Map.of(
                ModuleType.PHISHING, v1,
                ModuleType.FAKENEWS, v2
        );

        FusionRuleResult result = rule.evaluate(request, contributions);

        assertFalse(result.fired());
    }
}
