package com.trustshield.fusion.engine;

import com.trustshield.common.dto.FusionRuleResult;
import com.trustshield.common.dto.IncidentFusionRequest;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;

import java.util.Map;

/**
 * Contract for a named, deterministic, and auditable cross-modal fusion rule.
 */
public interface FusionRule {

    /**
     * Unique short identifier, e.g. "R1", "R2", "R3", "R4", "R5".
     */
    String getRuleId();

    /**
     * Human-readable rule title.
     */
    String getRuleName();

    /**
     * Rationale explaining why this rule exists and how it influences the verdict.
     */
    String getDescription();

    /**
     * Evaluates the rule against the incoming incident request and map of module verdicts.
     *
     * @param request incident fusion request with correlation ID and ledger status
     * @param contributions map of module types to individual module verdicts
     * @return result indicating whether the rule fired and what threat level it dictates
     */
    FusionRuleResult evaluate(IncidentFusionRequest request, Map<ModuleType, ModuleVerdict> contributions);
}
