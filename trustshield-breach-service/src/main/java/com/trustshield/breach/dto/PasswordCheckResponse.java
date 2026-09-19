package com.trustshield.breach.dto;

import java.util.List;
import java.util.Map;

import com.trustshield.breach.strength.StrengthAssessment;
import com.trustshield.common.dto.ModuleVerdict;

/**
 * Response to a password exposure check.
 *
 * @param verdict           the uniform cross-module verdict, consumable by fusion
 * @param recommendation    plain-language guidance from the threat level
 * @param strength          structural analysis, independent of breach membership
 * @param sourcesConsulted  per-source outcome, so the user can see that (say) the
 *                          range API was unavailable and only the local list ran
 * @param kAnonymous        whether every consulted source preserved k-anonymity.
 *                          True for this endpoint: neither the password nor its
 *                          full hash leaves the process.
 * @param bucketPrefix      the 5-hex-character SHA-1 bucket that would be sent to
 *                          the range API. Echoed so the privacy property is
 *                          visible rather than merely asserted — a viewer can
 *                          confirm only 5 of 40 characters are involved.
 */
public record PasswordCheckResponse(
        ModuleVerdict verdict,
        String recommendation,
        StrengthAssessment strength,
        List<SourceOutcome> sourcesConsulted,
        boolean kAnonymous,
        String bucketPrefix
) {

    /**
     * What one source reported.
     *
     * @param source      identifier, e.g. {@code PWNED_PASSWORDS_RANGE_API}
     * @param status      {@code EXPOSED}, {@code NOT_FOUND} or {@code UNAVAILABLE}
     * @param occurrences count when the source reports one, otherwise null. Null
     *                    means "this source does not know", never "zero".
     * @param detail      human-readable note, including why a source was unavailable
     */
    public record SourceOutcome(
            String source,
            String status,
            Long occurrences,
            String detail
    ) {
    }

    /** Compact shape for the dashboard, which does not need the full verdict. */
    public Map<String, Object> summary() {
        return Map.of(
                "riskScore", verdict.riskScore(),
                "threatLevel", verdict.threatLevel().name(),
                "verdict", verdict.verdict(),
                "degraded", verdict.degraded(),
                "weaknessScore", strength.weaknessScore()
        );
    }
}
