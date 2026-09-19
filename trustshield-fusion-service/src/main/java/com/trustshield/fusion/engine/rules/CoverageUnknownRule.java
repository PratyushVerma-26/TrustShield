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
 * Fusion Rule R3: Coverage Invariant (Refusal to Certify Safe).
 *
 * <p>Invariant: If any module returned {@link ThreatLevel#UNKNOWN}, operated in a degraded state,
 * or if no modules were provided, the composite incident can <em>never</em> be certified as {@link ThreatLevel#SAFE}.
 *
 * <p>Rationale: Enforces TrustShield's foundational rule — "absence of evidence is not evidence of absence".
 * If a video payload was recompressed (forensics inconclusive) or external fact check APIs were unreachable,
 * the platform refuses to falsely certify the overall event as clean or safe.
 */
@Component
@Order(3)
public class CoverageUnknownRule implements FusionRule {

    public static final String RULE_ID = "R3";
    public static final String RULE_NAME = "Coverage Invariant (Refusal to Certify Safe)";
    public static final String DESCRIPTION =
            "If any module returned UNKNOWN or degraded, the composite incident cannot be certified as SAFE.";

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
        if (contributions.isEmpty()) {
            return new FusionRuleResult(RULE_ID, RULE_NAME, DESCRIPTION, true, ThreatLevel.UNKNOWN);
        }

        boolean anyUnknownOrDegraded = contributions.values().stream()
                .anyMatch(v -> v.threatLevel() == ThreatLevel.UNKNOWN || v.degraded());

        return new FusionRuleResult(
                RULE_ID,
                RULE_NAME,
                DESCRIPTION,
                anyUnknownOrDegraded,
                anyUnknownOrDegraded ? ThreatLevel.UNKNOWN : null
        );
    }
}
