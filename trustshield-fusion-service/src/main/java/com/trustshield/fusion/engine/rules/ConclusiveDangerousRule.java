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
 * Fusion Rule R1: Conclusive Dangerous Escalation.
 *
 * <p>Invariant: If any individual security module returns a conclusive {@link ThreatLevel#DANGEROUS}
 * verdict (score >= 75 and {@code !degraded}), the composite incident is immediately deemed DANGEROUS.
 * A confirmed zero-day phishing link or verified deepfake cannot be diluted by other benign signals.
 */
@Component
@Order(1)
public class ConclusiveDangerousRule implements FusionRule {

    public static final String RULE_ID = "R1";
    public static final String RULE_NAME = "Conclusive Dangerous Escalation";
    public static final String DESCRIPTION =
            "Any single module returning a conclusive DANGEROUS verdict immediately escalates the incident to DANGEROUS.";

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
        boolean fired = contributions.values().stream()
                .anyMatch(v -> v.threatLevel() == ThreatLevel.DANGEROUS && !v.degraded());

        return new FusionRuleResult(
                RULE_ID,
                RULE_NAME,
                DESCRIPTION,
                fired,
                fired ? ThreatLevel.DANGEROUS : null
        );
    }
}
