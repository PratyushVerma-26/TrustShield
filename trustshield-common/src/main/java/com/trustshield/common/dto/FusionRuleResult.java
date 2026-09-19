package com.trustshield.common.dto;

import java.util.Objects;

/**
 * Outcome of evaluating an individual named fusion rule.
 *
 * @param ruleId e.g. "R1", "R2", "R3", "R4"
 * @param ruleName short name of the rule
 * @param description rule rationale
 * @param fired whether the rule condition was met
 * @param resultingLevel threat level resulting from this rule if fired, or null
 */
public record FusionRuleResult(
        String ruleId,
        String ruleName,
        String description,
        boolean fired,
        ThreatLevel resultingLevel
) {
    public FusionRuleResult {
        Objects.requireNonNull(ruleId, "ruleId must not be null");
        Objects.requireNonNull(ruleName, "ruleName must not be null");
        Objects.requireNonNull(description, "description must not be null");
    }
}
