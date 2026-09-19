package com.trustshield.common.dto;

/**
 * Severity band for any detection result across all four TrustShield modules.
 *
 * <p>A single shared scale is what lets the fusion service compare a phishing
 * verdict against a deepfake verdict against a fact-check verdict. Every module
 * must map its native confidence onto the same 0-100 risk score.
 *
 * <p>Band thresholds were chosen so that SAFE is genuinely safe: anything with
 * even weak positive evidence lands in SUSPICIOUS rather than SAFE, because the
 * cost of a missed phishing page is far higher than the cost of an extra warning.
 *
 * <h2>Semantics of UNKNOWN</h2>
 *
 * <p>The first four constants describe assessed threat levels. {@link #UNKNOWN}
 * represents an indeterminate state where evidence could not be gathered (e.g.
 * unreachable external sources or destructive recompression). This prevents
 * unverified targets from receiving a default {@code SAFE} rating.
 *
 * <p>{@code UNKNOWN} is placed last in declaration order. Prefer {@link #isConclusive()}
 * rather than ordinal comparisons.
 */
public enum ThreatLevel {

    SAFE(
            "No threat indicators found.",
            "This appears safe. Stay alert anyway if you were not expecting this message."
    ),
    LOW(
            "Weak or ambiguous threat indicators.",
            "Probably fine, but verify the sender through a channel you already trust."
    ),
    SUSPICIOUS(
            "Multiple threat indicators present.",
            "Do not enter passwords, OTPs or payment details. Verify independently before acting."
    ),
    DANGEROUS(
            "Strong threat indicators. High confidence of malicious intent.",
            "Do not interact with this. Do not click, reply, pay or share credentials. Delete it."
    ),

    /**
     * Nothing was assessed. Not a severity band; see the class javadoc.
     *
     * <p>Use this whenever a verdict's risk score carries no information — every
     * source unavailable, a lookup the user declined to authorise, input the module
     * cannot read. Never use it for "we looked and found nothing", which is
     * {@link #SAFE}.
     */
    UNKNOWN(
            "Not assessed. No evidence was gathered in either direction.",
            "This could not be checked, so treat the result as unknown rather than clean."
    );

    private final String description;
    private final String recommendation;

    ThreatLevel(String description, String recommendation) {
        this.description = description;
        this.recommendation = recommendation;
    }

    public String getDescription() {
        return description;
    }

    /** Plain-language guidance intended for a non-technical end user. */
    public String getRecommendation() {
        return recommendation;
    }

    /**
     * Maps a 0-100 risk score onto a severity band.
     *
     * <p>Never returns {@link #UNKNOWN}: a score alone cannot tell you whether it
     * was computed from evidence or from the absence of any. Only the module that
     * ran the checks knows that, which is why {@code UNKNOWN} has to be set
     * explicitly by the caller.
     *
     * @param riskScore risk score; values outside 0-100 are clamped
     */
    public static ThreatLevel fromScore(int riskScore) {
        int clamped = Math.max(0, Math.min(100, riskScore));
        if (clamped >= 75) {
            return DANGEROUS;
        }
        if (clamped >= 40) {
            return SUSPICIOUS;
        }
        if (clamped >= 15) {
            return LOW;
        }
        return SAFE;
    }

    /** True when this level warrants actively blocking or interrupting the user. */
    public boolean warrantsBlocking() {
        return this == DANGEROUS || this == SUSPICIOUS;
    }

    /**
     * True when this level reflects an actual finding.
     *
     * <p>The one guard any presentation layer needs: a badge, colour, icon or
     * summary sentence derived from an inconclusive verdict is a claim the system
     * has not earned. Check this before rendering, and never infer safety from
     * {@code !warrantsBlocking()} — {@link #UNKNOWN} does not warrant blocking
     * either.
     */
    public boolean isConclusive() {
        return this != UNKNOWN;
    }
}
