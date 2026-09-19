package com.trustshield.fakenews.simhash;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimHashMatcherTest {

    @Test
    @DisplayName("Empty or blank strings produce 0 hash")
    void emptyOrBlankStrings() {
        assertEquals(0L, SimHashMatcher.computeHash(null));
        assertEquals(0L, SimHashMatcher.computeHash(""));
        assertEquals(0L, SimHashMatcher.computeHash("   "));
        assertEquals(0L, SimHashMatcher.computeHash("---!!!???"));
    }

    @Test
    @DisplayName("Identical text produces identical hash, 0 Hamming distance, and 1.0 similarity")
    void identicalText() {
        String text = "Government announces free laptop scheme for all students";
        long h1 = SimHashMatcher.computeHash(text);
        long h2 = SimHashMatcher.computeHash(text);

        assertEquals(h1, h2);
        assertEquals(0, SimHashMatcher.hammingDistance(h1, h2));
        assertEquals(1.0, SimHashMatcher.similarity(h1, h2));
    }

    @Test
    @DisplayName("Near-duplicate text with minor variations produces high similarity")
    void nearDuplicateVariations() {
        String original = "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world";
        String variant = "Breaking news: UNESCO declared Indian national anthem Jana Gana Mana best in the world! Share this forward.";

        long h1 = SimHashMatcher.computeHash(original);
        long h2 = SimHashMatcher.computeHash(variant);

        int distance = SimHashMatcher.hammingDistance(h1, h2);
        double sim = SimHashMatcher.similarity(h1, h2);

        // Near-duplicates typically differ by fewer than 15 bits out of 64
        assertTrue(distance <= 14, "Hamming distance was " + distance);
        assertTrue(sim >= 0.78, "Similarity was " + sim);
    }

    @Test
    @DisplayName("Completely unrelated texts have low similarity")
    void unrelatedTexts() {
        String text1 = "Drinking lemon juice with baking soda cures cancer immediately";
        String text2 = "Quantum computing algorithms for portfolio optimization in financial markets";

        long h1 = SimHashMatcher.computeHash(text1);
        long h2 = SimHashMatcher.computeHash(text2);

        double sim = SimHashMatcher.similarity(h1, h2);
        assertTrue(sim < 0.75, "Similarity should be low for unrelated topics: " + sim);
    }

    @Test
    @DisplayName("Token extraction filters stop words and punctuation")
    void tokenExtraction() {
        List<String> tokens = SimHashMatcher.extractTokens("This is a simple test with punctuation, numbers 123, and common words!");
        assertFalse(tokens.contains("this"));
        assertFalse(tokens.contains("is"));
        assertFalse(tokens.contains("a"));
        assertFalse(tokens.contains("with"));
        assertFalse(tokens.contains("and"));
        assertTrue(tokens.contains("simple"));
        assertTrue(tokens.contains("test"));
        assertTrue(tokens.contains("punctuation"));
    }
}
