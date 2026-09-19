package com.trustshield.breach.strength;

import java.util.List;

/**
 * Structural assessment of a password.
 *
 * @param length                  character count
 * @param characterClasses        how many of {lower, upper, digit, symbol} are present
 * @param charsetSize             size of the alphabet implied by those classes
 * @param theoreticalBits         {@code length * log2(charsetSize)} — see the
 *                                warning on {@link PasswordStrengthAnalyzer}.
 *                                This is an upper bound that human-chosen
 *                                passwords do not reach.
 * @param weaknesses              structural problems found, each with an explanation
 * @param weaknessScore           0-100, higher means weaker. Derived from the
 *                                weaknesses, not from {@code theoreticalBits}.
 * @param assumedGuessesPerSecond the attack rate assumed by {@code bruteForceEstimate}.
 *                                Reported alongside it so the figure is never
 *                                quoted without its assumption.
 * @param bruteForceEstimate      plain-language exhaustive-search time at that
 *                                rate, for a password of this shape chosen
 *                                uniformly at random. A real attacker guessing a
 *                                human password does far better than this.
 */
public record StrengthAssessment(
        int length,
        int characterClasses,
        int charsetSize,
        double theoreticalBits,
        List<Weakness> weaknesses,
        int weaknessScore,
        long assumedGuessesPerSecond,
        String bruteForceEstimate
) {

    public StrengthAssessment {
        weaknesses = weaknesses == null ? List.of() : List.copyOf(weaknesses);
        weaknessScore = Math.max(0, Math.min(100, weaknessScore));
    }

    /**
     * A single structural problem.
     *
     * @param code        machine-readable identifier, e.g. {@code KEYBOARD_WALK}
     * @param description plain-language explanation for the end user
     * @param penalty     points added to {@code weaknessScore}
     */
    public record Weakness(String code, String description, int penalty) {
    }
}
