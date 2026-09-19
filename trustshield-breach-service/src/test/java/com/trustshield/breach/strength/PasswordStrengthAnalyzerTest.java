package com.trustshield.breach.strength;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for structural password analysis.
 *
 * <p>Every expected value here was computed by running an independent port of
 * {@code findWeaknesses} over the same inputs, rather than reasoned about by
 * reading the regexes. That practice comes directly from the phishing module,
 * where a hand-reasoned assertion about Shannon entropy turned out to be false
 * and had propagated into user-facing copy before a test caught it.
 */
class PasswordStrengthAnalyzerTest {

    private final PasswordStrengthAnalyzer analyzer = new PasswordStrengthAnalyzer();

    private static List<String> codes(StrengthAssessment a) {
        return a.weaknesses().stream().map(StrengthAssessment.Weakness::code).toList();
    }

    @Test
    @DisplayName("an empty password is reported as empty, not as strong")
    void emptyPassword() {
        StrengthAssessment a = analyzer.analyze("");
        assertEquals(List.of("EMPTY"), codes(a));
        assertEquals(100, a.weaknessScore());
        assertEquals(0.0, a.theoreticalBits());
        assertEquals("instant", a.bruteForceEstimate());
    }

    @Test
    @DisplayName("null is treated as empty rather than throwing")
    void nullPassword() {
        StrengthAssessment a = analyzer.analyze(null);
        assertEquals(List.of("EMPTY"), codes(a));
        assertEquals(0, a.length());
    }

    @Test
    @DisplayName("short, single-class, repetitive")
    void shortAndRepetitive() {
        StrengthAssessment a = analyzer.analyze("aaa");
        assertEquals(
                List.of("TOO_SHORT", "SINGLE_CHARACTER_CLASS", "REPEATED_CHARACTERS"),
                codes(a));
        assertEquals(85, a.weaknessScore());
        assertEquals(1, a.characterClasses());
        assertEquals(26, a.charsetSize());
    }

    @Test
    @DisplayName("a dictionary word is caught by structure alone")
    void dictionaryWord() {
        StrengthAssessment a = analyzer.analyze("password");
        assertEquals(
                List.of("SHORT", "SINGLE_CHARACTER_CLASS", "COMMON_BASE_WORD"),
                codes(a));
        assertEquals(80, a.weaknessScore());
        // Note what is NOT asserted: which base word is named. "password" contains
        // both "pass" and "password", and findCommonBase iterates a Set, so the
        // reported word is whichever the Set yields first. Asserting one would be
        // asserting an implementation detail that HashSet does not promise.
    }

    /**
     * The point of the whole class, in one test.
     *
     * <p>{@code Password123!} scores nearly 79 bits by the standard
     * {@code length * log2(charset)} formula — a figure that would look excellent
     * on a dashboard — while being among the first strings any cracking dictionary
     * tries. The bits figure is an upper bound assuming uniform random generation;
     * this password is not that. So the operative number must be the structural
     * one, and this test pins the divergence between them.
     */
    @Test
    @DisplayName("high theoretical bits does not mean strong")
    void theoreticalBitsIsAnUpperBoundNotAStrengthRating() {
        StrengthAssessment a = analyzer.analyze("Password123!");

        assertEquals(4, a.characterClasses(), "all four character classes present");
        assertEquals(94, a.charsetSize());
        assertTrue(a.theoreticalBits() > 78.0 && a.theoreticalBits() < 79.0,
                "12 * log2(94) is about 78.66, got " + a.theoreticalBits());

        // And yet:
        assertTrue(codes(a).contains("COMMON_BASE_WORD"));
        assertTrue(codes(a).contains("WORD_PLUS_DIGITS"));
        assertEquals(55, a.weaknessScore(),
                "structure must override the flattering bits figure");
        assertFalse(codes(a).contains("NONE"));
    }

    @Test
    @DisplayName("keyboard walks are detected")
    void keyboardWalk() {
        StrengthAssessment a = analyzer.analyze("qwerty123");
        assertEquals(
                List.of("SHORT", "KEYBOARD_WALK", "COMMON_BASE_WORD", "WORD_PLUS_DIGITS"),
                codes(a));
        assertEquals(100, a.weaknessScore(), "penalties sum to exactly the 100 ceiling");
    }

    @Test
    @DisplayName("an all-digit sequence trips several independent checks")
    void digitSequence() {
        StrengthAssessment a = analyzer.analyze("12345678");
        assertEquals(
                List.of("SHORT", "SINGLE_CHARACTER_CLASS", "DIGITS_ONLY",
                        "SEQUENTIAL_CHARACTERS", "KEYBOARD_WALK", "WORD_PLUS_DIGITS"),
                codes(a));
        assertEquals(100, a.weaknessScore(), "raw penalties total 140 and are clamped to 100");
        assertEquals(10, a.charsetSize());
    }

    @Test
    @DisplayName("a generated password produces the zero-penalty NONE marker")
    void structurallyClean() {
        StrengthAssessment a = analyzer.analyze("Xq7#vLm2$pRt9wZk");
        assertEquals(List.of("NONE"), codes(a));
        assertEquals(0, a.weaknessScore());
        assertTrue(a.bruteForceEstimate().contains("universe"),
                "16 characters over a 94-symbol alphabet is ~105 bits");

        // NONE must still carry a zero penalty, so it can never raise a score.
        assertEquals(0, a.weaknesses().get(0).penalty());
        // And its description must not claim safety, because this class cannot
        // know whether the password has leaked. Only the corpus check knows that.
        assertTrue(a.weaknesses().get(0).description().contains("separate check"));
    }

    @Test
    @DisplayName("a long passphrase is not penalised for lacking symbols")
    void passphrase() {
        StrengthAssessment a = analyzer.analyze("correct-horse-battery-staple");
        assertEquals(List.of("NONE"), codes(a));
        assertEquals(0, a.weaknessScore());
        assertEquals(28, a.length());
    }

    @Test
    @DisplayName("the assumed attack rate travels with the estimate")
    void attackRateIsAlwaysReported() {
        // The estimate is meaningless without the rate it assumes. Quoting a
        // crack time with no stated rate is the same overclaim as quoting entropy
        // bits as though they measured resistance.
        StrengthAssessment a = analyzer.analyze("Xq7#vLm2$pRt9wZk");
        assertEquals(10_000_000_000L, a.assumedGuessesPerSecond());
    }

    @Test
    @DisplayName("time units are singular where appropriate")
    void unitsRead() {
        // Trivial, but this exact case rendered as "1 hours" before it was fixed,
        // and it would have rendered that way on the demo screen.
        StrengthAssessment a = analyzer.analyze("qwerty123");
        assertFalse(a.bruteForceEstimate().startsWith("1 hours"),
                "got: " + a.bruteForceEstimate());
        assertEquals("1 hour", a.bruteForceEstimate());
    }
}
