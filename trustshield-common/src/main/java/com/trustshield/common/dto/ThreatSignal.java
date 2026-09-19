package com.trustshield.common.dto;

/**
 * A single piece of evidence contributing to a detection verdict.
 *
 * <p>Signals provide the explainability layer. Rather than returning a bare score,
 * every TrustShield module returns the list of signals that produced it, providing
 * clear attribution for users and auditable evidence for security reviews.
 *
 * @param name         short machine-readable identifier, e.g. {@code IP_LITERAL_HOST}
 * @param description  plain-language explanation shown to the end user
 * @param contribution points this signal added to the risk score (may be negative
 *                     for signals that reduce suspicion, e.g. a long-lived domain)
 * @param triggered    whether this signal actually fired; untriggered signals are
 *                     retained so the UI can show what was checked and passed
 * @param source       where the evidence came from, e.g. {@code LEXICAL_MODEL},
 *                     {@code VIRUSTOTAL}, {@code ELA_FORENSICS}
 */
public record ThreatSignal(
        String name,
        String description,
        int contribution,
        boolean triggered,
        String source
) {

    /** A signal that fired and added risk. */
    public static ThreatSignal triggered(String name, String description, int contribution, String source) {
        return new ThreatSignal(name, description, contribution, true, source);
    }

    /** A check that was performed and passed, contributing no risk. */
    public static ThreatSignal passed(String name, String description, String source) {
        return new ThreatSignal(name, description, 0, false, source);
    }

    /** A signal that actively reduces suspicion. */
    public static ThreatSignal mitigating(String name, String description, int reduction, String source) {
        return new ThreatSignal(name, description, -Math.abs(reduction), true, source);
    }
}
