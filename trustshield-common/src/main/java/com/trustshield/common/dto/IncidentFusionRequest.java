package com.trustshield.common.dto;

import java.util.List;

/**
 * Request to perform cross-modal risk fusion over multiple module verdicts.
 *
 * @param incidentId correlation identifier
 * @param verdicts list of individual verdicts from phishing, deepfake, breach, or fakenews
 * @param ledgerVerified whether the integrity ledger validated successfully for this incident
 */
public record IncidentFusionRequest(
        IncidentId incidentId,
        List<ModuleVerdict> verdicts,
        boolean ledgerVerified
) {
    public IncidentFusionRequest {
        incidentId = incidentId != null ? incidentId : IncidentId.generate();
        verdicts = verdicts == null ? List.of() : List.copyOf(verdicts);
    }
}
