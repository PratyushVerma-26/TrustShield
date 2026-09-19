package com.trustshield.phishing.dto;

import com.trustshield.common.dto.ThreatLevel;

import java.time.Instant;

/**
 * Compact view of a past scan, for the history endpoint.
 *
 * <p>A projection rather than the JPA entity, so the persistence schema is not
 * part of the public API contract.
 */
public record ScanHistoryItem(
        Long id,
        String url,
        int riskScore,
        ThreatLevel threatLevel,
        String verdict,
        long latencyMs,
        boolean degraded,
        Instant scannedAt
) {
}
