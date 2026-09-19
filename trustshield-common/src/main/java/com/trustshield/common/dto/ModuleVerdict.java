package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.Collections;
import java.util.List;

/**
 * The uniform verdict shape emitted by every detection module.
 *
 * <p>Having one verdict type across phishing, deepfake, breach and misinformation
 * is what makes cross-modal fusion possible: the fusion service can reason over a
 * heterogeneous set of verdicts without knowing how each was produced.
 *
 * @param module       which detector produced this
 * @param riskScore    0-100, where 100 is certainly malicious. Meaningless when
 *                     {@code threatLevel} is {@code UNKNOWN}: 0 then records that
 *                     nothing was measured, not that nothing was found.
 * @param threatLevel  severity band derived from {@code riskScore}, or
 *                     {@code UNKNOWN} when the module assessed nothing
 * @param verdict      short machine-readable outcome, e.g. {@code PHISHING_DETECTED}
 * @param explanation  one or two sentences of plain language for the end user
 * @param signals      the evidence behind the score
 * @param latencyMs    wall-clock time taken to produce this verdict
 * @param evaluatedAt  when the evaluation completed
 * @param degraded     true when the verdict was produced without all intended
 *                     inputs (e.g. an external API timed out). Callers should
 *                     present degraded verdicts with lower confidence rather than
 *                     treating them as authoritative. Always true when
 *                     {@code threatLevel} is {@code UNKNOWN}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ModuleVerdict(
        ModuleType module,
        int riskScore,
        ThreatLevel threatLevel,
        String verdict,
        String explanation,
        List<ThreatSignal> signals,
        long latencyMs,
        Instant evaluatedAt,
        boolean degraded
) {

    /**
     * Canonical constructor: clamps the score, derives the level from it, and
     * enforces the one cross-field invariant this record has.
     *
     * <p>{@code UNKNOWN} implies {@code degraded}. A verdict that assessed nothing
     * is by definition missing its intended inputs, so the flag is forced rather
     * than trusted — any of the six construction paths could otherwise ship an
     * {@code UNKNOWN} verdict that a caller reads as authoritative. Cheaper to make
     * the combination unrepresentable than to audit for it again.
     */
    public ModuleVerdict {
        riskScore = Math.max(0, Math.min(100, riskScore));
        threatLevel = threatLevel == null ? ThreatLevel.fromScore(riskScore) : threatLevel;
        degraded = degraded || threatLevel == ThreatLevel.UNKNOWN;
        signals = signals == null ? List.of() : List.copyOf(signals);
        evaluatedAt = evaluatedAt == null ? Instant.now() : evaluatedAt;
    }

    public static ModuleVerdict of(ModuleType module,
                                   int riskScore,
                                   String verdict,
                                   String explanation,
                                   List<ThreatSignal> signals,
                                   long latencyMs) {
        return new ModuleVerdict(
                module,
                riskScore,
                ThreatLevel.fromScore(riskScore),
                verdict,
                explanation,
                signals,
                latencyMs,
                Instant.now(),
                false
        );
    }

    /**
     * A verdict produced with incomplete inputs. Used when an external dependency
     * fails: the system still answers, but says so.
     */
    public static ModuleVerdict degraded(ModuleType module,
                                         int riskScore,
                                         String verdict,
                                         String explanation,
                                         List<ThreatSignal> signals,
                                         long latencyMs) {
        return new ModuleVerdict(
                module,
                riskScore,
                ThreatLevel.fromScore(riskScore),
                verdict,
                explanation,
                signals,
                latencyMs,
                Instant.now(),
                true
        );
    }

    /**
     * A verdict that assessed nothing, because no source could be consulted.
     *
     * <p>Distinct from {@link #degraded} in a way that matters. A degraded verdict
     * has a score that means something and a caveat attached: the phishing module
     * scoring a URL at 100 from lexical features while a reputation API was down is
     * degraded, and reporting {@code DANGEROUS} is correct. This factory is for the
     * other case — the score is 0 because nothing was learned, not because nothing
     * was found. Those two produce identical numbers and opposite meanings, so the
     * severity band is pinned to {@link ThreatLevel#UNKNOWN} instead of being
     * derived from the score.
     *
     * <p>Modules should reach for this only when the question they were asked went
     * genuinely unanswered. Partial evidence is {@link #degraded}.
     */
    public static ModuleVerdict inconclusive(ModuleType module,
                                             String verdict,
                                             String explanation,
                                             List<ThreatSignal> signals,
                                             long latencyMs) {
        return new ModuleVerdict(
                module,
                0,
                ThreatLevel.UNKNOWN,
                verdict,
                explanation,
                signals,
                latencyMs,
                Instant.now(),
                true
        );
    }

    /**
     * A verdict for input this module cannot assess at all. Deliberately scores 0
     * rather than guessing, so fusion can ignore it instead of averaging in noise.
     *
     * <p>Reports {@link ThreatLevel#UNKNOWN}, not {@code SAFE}. "This module cannot
     * read your file" and "your file is clean" are not the same statement, and a
     * score of 0 is the only thing they have in common.
     */
    public static ModuleVerdict notApplicable(ModuleType module, String reason) {
        return new ModuleVerdict(
                module, 0, ThreatLevel.UNKNOWN, "NOT_APPLICABLE", reason,
                Collections.emptyList(), 0L, Instant.now(), true
        );
    }

    /** Only the signals that actually fired, for compact UI display. */
    public List<ThreatSignal> triggeredSignals() {
        return signals.stream().filter(ThreatSignal::triggered).toList();
    }

    /**
     * True when this verdict is a real answer rather than a report of ignorance.
     *
     * <p>Convenience for the presentation layer and, later, for fusion: an
     * inconclusive verdict must not be folded into an aggregate score as though it
     * were a clean result.
     */
    @JsonIgnore
    public boolean isConclusive() {
        return threatLevel.isConclusive();
    }
}
