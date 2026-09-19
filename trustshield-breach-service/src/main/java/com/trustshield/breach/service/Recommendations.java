package com.trustshield.breach.service;

import com.trustshield.common.dto.ThreatLevel;

/**
 * Contextual recommendation generator for credential and breach verification verdicts.
 *
 * <p>Dispatches plain-language guidance tailored to credential security, resolving
 * recommendations by verdict state first, and then falling through to severity bands
 * only when lookups produce conclusive answers.
 */
final class Recommendations {

    private Recommendations() {
    }

    /** Guidance for a password check. */
    static String forPasswordCheck(String verdictCode, ThreatLevel level, boolean anyWeakness) {
        return switch (verdictCode) {
            case "PASSWORD_EXPOSED" -> "Change this password now, everywhere you have used it. "
                    + "It is in a published breach corpus, which means it is already in the "
                    + "wordlists attackers try first. Use a unique password per account, and "
                    + "turn on two-factor authentication where it is offered.";

            case "INCONCLUSIVE" -> "This check could not be completed, so treat the result as "
                    + "unknown rather than clean. No breach source could be reached. "
                    + (anyWeakness
                            ? "Independently of that, the structural observations below are worth acting on."
                            : "Retry when connectivity is available.");

            case "NO_EXPOSURE_FOUND" -> switch (level) {
                case DANGEROUS, SUSPICIOUS -> "This password was not found in the corpora "
                        + "consulted, but its structure is predictable enough that a dictionary "
                        + "or rule-based attack would likely reach it. Prefer a longer "
                        + "passphrase or a generated password.";
                case LOW -> "Not found in the corpora consulted, and no serious structural "
                        + "problem was detected. Length is still the cheapest improvement "
                        + "available.";
                case SAFE -> "Not found in the corpora consulted, and no structural weakness "
                        + "was detected. Note this is not proof of safety: no corpus contains "
                        + "every breach.";
                // Exhaustive switch handling: fallback if state and level diverge
                case UNKNOWN -> "No source could be reached, so nothing is known either way. "
                        + "Do not treat this as a clean verdict.";
            };

            default -> "Result unavailable. Do not treat this as a clean verdict.";
        };
    }

    /** Guidance for an email check. */
    static String forEmailCheck(String verdictCode, int breachCount) {
        return switch (verdictCode) {
            case "EMAIL_EXPOSED" -> "This address appears in " + breachCount + " known breach(es). "
                    + "Change the password on each affected service, and anywhere you reused it. "
                    + "Enable two-factor authentication, and be sceptical of messages that cite "
                    + "details from these breaches to sound credible.";

            case "NO_EXPOSURE_FOUND" -> "This address was not found in the breaches known to the "
                    + "source. That is reassuring but not proof: breaches that are undisclosed, "
                    + "unreported or not yet public cannot appear in any corpus.";

            case "SOURCE_UNAVAILABLE" -> "No lookup was performed, so nothing is known either "
                    + "way. This endpoint needs a Have I Been Pwned API key. The password check "
                    + "needs no key and works offline.";

            case "NOT_APPLICABLE" -> "No lookup was performed. This check transmits your full "
                    + "email address to a third party, so it will not run without your explicit "
                    + "acknowledgement. Nothing was sent.";

            case "INCONCLUSIVE" -> "The lookup failed, so treat this as unknown rather than "
                    + "clean. Retry before drawing any conclusion.";

            default -> "Result unavailable. Do not treat this as a clean verdict.";
        };
    }
}
