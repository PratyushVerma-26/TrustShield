package com.trustshield.common.dto;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Synthesized cross-modal threat verdict.
 *
 * <p>Evaluated using named, auditable rules (R1-R4) rather than opaque weights or
 * learned combiners:
 * <ul>
 *   <li><b>R1</b>: Any conclusive DANGEROUS makes the incident DANGEROUS.</li>
 *   <li><b>R2</b>: Two or more SUSPICIOUS verdicts across different modalities escalate to DANGEROUS.</li>
 *   <li><b>R3</b>: The coverage rule: if any module returned UNKNOWN, the aggregate can never be SAFE.</li>
 *   <li><b>R4</b>: A ledger mismatch overrides everything.</li>
 * </ul>
 *
 * @param incidentId correlation identifier
 * @param aggregateVerdict unified verdict representing the incident
 * @param firedRules list of all fusion rules and whether they fired
 * @param contributions map of module type to individual module verdict
 * @param coverageMap map showing which modules were evaluated conclusively
 * @param ledgerVerified whether ledger integrity was confirmed
 * @param safeDisallowedByUnknown true if R3 prevented a SAFE designation due to unmeasured modalities
 */
public record IncidentFusionResponse(
        IncidentId incidentId,
        ModuleVerdict aggregateVerdict,
        List<FusionRuleResult> firedRules,
        Map<ModuleType, ModuleVerdict> contributions,
        Map<ModuleType, Boolean> coverageMap,
        boolean ledgerVerified,
        boolean safeDisallowedByUnknown
) {
    public IncidentFusionResponse {
        Objects.requireNonNull(incidentId, "incidentId must not be null");
        Objects.requireNonNull(aggregateVerdict, "aggregateVerdict must not be null");
        firedRules = firedRules == null ? List.of() : List.copyOf(firedRules);
        contributions = contributions == null ? Map.of() : Map.copyOf(contributions);
        coverageMap = coverageMap == null ? Map.of() : Map.copyOf(coverageMap);
    }
}
