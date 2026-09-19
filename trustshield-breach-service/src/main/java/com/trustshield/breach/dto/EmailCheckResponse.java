package com.trustshield.breach.dto;

import java.util.List;

import com.trustshield.common.dto.ModuleVerdict;

/**
 * Response to an email breach check.
 *
 * @param verdict        the uniform cross-module verdict
 * @param recommendation plain-language guidance from the threat level
 * @param breaches       breaches as reported by the upstream source. Empty when
 *                       the lookup was unavailable — empty here means "we do not
 *                       know", which is why {@code verdict.degraded()} is set.
 * @param kAnonymous     always false for this endpoint, and reported explicitly.
 *                       The full address is transmitted; there is no range
 *                       variant of the breached-account API.
 * @param privacyNotice  what was actually sent where, in plain language
 */
public record EmailCheckResponse(
        ModuleVerdict verdict,
        String recommendation,
        List<BreachSummary> breaches,
        boolean kAnonymous,
        String privacyNotice
) {

    public EmailCheckResponse {
        breaches = breaches == null ? List.of() : List.copyOf(breaches);
    }

    /**
     * One breach, carrying only what the upstream source stated.
     *
     * @param name        breach identifier from the source
     * @param title       display name from the source
     * @param domain      affected domain from the source
     * @param breachDate  date as reported, not inferred
     * @param pwnCount    affected-account count as reported. Null when the source
     *                    did not supply one; never estimated locally.
     * @param dataClasses categories of data exposed, as reported
     * @param verified    whether the source considers the breach verified
     */
    public record BreachSummary(
            String name,
            String title,
            String domain,
            String breachDate,
            Integer pwnCount,
            List<String> dataClasses,
            Boolean verified
    ) {
        public BreachSummary {
            dataClasses = dataClasses == null ? List.of() : List.copyOf(dataClasses);
        }
    }
}
