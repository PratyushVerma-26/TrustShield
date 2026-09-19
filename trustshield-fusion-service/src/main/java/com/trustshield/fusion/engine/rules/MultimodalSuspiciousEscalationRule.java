package com.trustshield.fusion.engine.rules;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fusion.engine.FusionRule;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Fusion Rule R2: Multi-Modal Suspicious Escalation.
 *
 * <p>Invariant: Two or more distinct modalities returning {@link ThreatLevel#SUSPICIOUS}
 * verdicts escalate the aggregate incident to {@link ThreatLevel#DANGEROUS}.
 *
 * <p>Rationale: A slightly suspicious domain alongside a slightly unnatural audio recording
 * represents a coordinated multi-vector lure. The probability of independent false positives
 * co-occurring across distinct modalities is significantly lower than in isolation.
 */
@Component
@Order(2)
public class MultimodalSuspiciousEscalationRule implements FusionRule {

    public static final String RULE_ID = "R2";
    public static final String RULE_NAME = "Multi-Modal Suspicious Escalation";
    public static final String DESCRIPTION =
            "Two or more distinct modalities returning SUSPICIOUS verdicts escalate the aggregate incident to DANGEROUS.";

    @Override
    public String getRuleId() {
        return RULE_ID;
    }

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public FusionRuleResult evaluate(IncidentFusionRequest request, Map<ModuleType, ModuleVerdict> contributions) {
        long suspiciousCount = contributions.values().stream()
                .filter(v -> v.threatLevel() == ThreatLevel.SUSPICIOUS)
                .count();

        boolean fired = suspiciousCount >= 2;

        return new FusionRuleResult(
                RULE_ID,
                RULE_NAME,
                DESCRIPTION,
                fired,
                fired ? ThreatLevel.DANGEROUS : null
        );
    }
}
