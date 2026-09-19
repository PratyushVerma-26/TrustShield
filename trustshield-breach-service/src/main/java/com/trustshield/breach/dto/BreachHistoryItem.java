package com.trustshield.breach.dto;

import java.time.Instant;

import com.trustshield.breach.entity.BreachCheckRecord;
import com.trustshield.common.dto.ThreatLevel;

/**
 * Compact view of a past breach check, for the history endpoint.
 *
 * <p>A projection rather than the JPA entity, so the persistence schema is not
 * part of the public API contract.
 *
 * <p>Note what a history row can and cannot show. For a password check it shows
 * the 5-character bucket prefix — deliberately useless for identifying the
 * password, since it covers roughly a millionth of the SHA-1 space. For an email
 * check it shows a truncated hash, not the address. There is no field here that
 * could be widened later to include the secret, because the entity does not hold
 * one.
 *
 * @param id         audit row identifier
 * @param checkType  PASSWORD or EMAIL
 * @param subject    bucket prefix for passwords, or the first 12 hex characters
 *                   of the subject hash for emails. Never the input itself.
 * @param riskScore  0-100
 * @param threatLevel derived band
 * @param verdict    machine-readable outcome code
 * @param exposed    whether any source confirmed exposure
 * @param degraded   whether at least one intended source was unavailable
 * @param checkedAt  when the check ran
 */
public record BreachHistoryItem(
        Long id,
        BreachCheckRecord.CheckType checkType,
        String subject,
        int riskScore,
        ThreatLevel threatLevel,
        String verdict,
        boolean exposed,
        boolean degraded,
        Instant checkedAt
) {

    /** Builds the projection, choosing the safe subject representation per type. */
    public static BreachHistoryItem from(BreachCheckRecord record) {
        String subject = switch (record.getCheckType()) {
            case PASSWORD -> record.getBucketPrefix();
            case EMAIL -> abbreviate(record.getSubjectHash());
        };
        return new BreachHistoryItem(
                record.getId(),
                record.getCheckType(),
                subject,
                record.getRiskScore(),
                record.getThreatLevel(),
                record.getVerdict(),
                record.isExposed(),
                record.isDegraded(),
                record.getCheckedAt());
    }

    private static String abbreviate(String hash) {
        if (hash == null) {
            return null;
        }
        return hash.length() <= 12 ? hash : hash.substring(0, 12) + "...";
    }
}
