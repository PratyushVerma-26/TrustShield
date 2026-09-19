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
 * Fusion Rule R5: Cross-Modal Synergistic Attack Multiplier.
 *
 * <p>Invariant: Co-occurrence of social engineering lures (PHISHING) alongside synthetic media (DEEPFAKE)
 * or viral misinformation (FAKENEWS) indicates a coordinated multi-vector campaign (e.g. CEO fraud
 * voice clone directing victim to a phishing portal, or a fake government grant scheme with a credential harvesting link).
 */
@Component
@Order(5)
public class CrossModalCoordinationRule implements FusionRule {

    public static final String RULE_ID = "R5";
    public static final String RULE_NAME = "Cross-Modal Synergistic Attack Multiplier";
    public static final String DESCRIPTION =
            "Co-occurrence of credential/social engineering lures (PHISHING) with synthetic media (DEEPFAKE) or viral deception (FAKENEWS).";

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
        ModuleVerdict phishing = contributions.get(ModuleType.PHISHING);
        ModuleVerdict deepfake = contributions.get(ModuleType.DEEPFAKE);
        ModuleVerdict fakenews = contributions.get(ModuleType.FAKENEWS);

        boolean hasPhishing = phishing != null && phishing.riskScore() >= 25;
        boolean hasDeepfake = deepfake != null && deepfake.riskScore() >= 25;
        boolean hasFakenews = fakenews != null && fakenews.riskScore() >= 25;

        boolean fired = hasPhishing && (hasDeepfake || hasFakenews);

        ThreatLevel level = null;
        if (fired) {
            boolean anySevere = (phishing.riskScore() >= 60) ||
                    (hasDeepfake && deepfake.riskScore() >= 60) ||
                    (hasFakenews && fakenews.riskScore() >= 60);
            level = anySevere ? ThreatLevel.DANGEROUS : ThreatLevel.SUSPICIOUS;
        }

        return new FusionRuleResult(
                RULE_ID,
                RULE_NAME,
                DESCRIPTION,
                fired,
                level
        );
    }
}
