package com.trustshield.common.dto;

import java.util.Objects;

/**
 * Request to commit a module verdict or incident result to the append-only ledger.
 *
 * @param incidentId correlation identifier
 * @param module which detector emitted the verdict
 * @param canonicalVerdictJson canonical JSON representation of the verdict or incident
 */
public record LedgerAppendRequest(
        IncidentId incidentId,
        ModuleType module,
        String canonicalVerdictJson
) {
    public LedgerAppendRequest {
        Objects.requireNonNull(incidentId, "incidentId must not be null");
        Objects.requireNonNull(module, "module must not be null");
        Objects.requireNonNull(canonicalVerdictJson, "canonicalVerdictJson must not be null");
    }
}
