package com.trustshield.phishing.reputation;

/**
 * Result of consulting one external reputation source.
 *
 * <p>Implements a three-state outcome model: {@code available=false} indicates the source could
 * not be reached or returned no data, distinct from a verified clean finding.
 * This prevents API timeouts from being conflated with clean verdicts.
 *
 * @param source    identifier, e.g. {@code GOOGLE_SAFE_BROWSING}
 * @param available whether a usable answer was obtained at all
 * @param flagged   whether the source considers the URL malicious; only
 *                  meaningful when {@code available} is true
 * @param rawScore  source-specific score where one exists (e.g. VirusTotal's
 *                  proportion of engines flagging), else null
 * @param detail    short human-readable note for the audit trail
 */
public record ReputationVerdict(
        String source,
        boolean available,
        boolean flagged,
        Integer rawScore,
        String detail
) {

    public static ReputationVerdict flagged(String source, Integer rawScore, String detail) {
        return new ReputationVerdict(source, true, true, rawScore, detail);
    }

    public static ReputationVerdict clean(String source, Integer rawScore, String detail) {
        return new ReputationVerdict(source, true, false, rawScore, detail);
    }

    /** Source could not be consulted: disabled, unreachable, rate-limited, or no data. */
    public static ReputationVerdict unavailable(String source, String reason) {
        return new ReputationVerdict(source, false, false, null, reason);
    }
}
