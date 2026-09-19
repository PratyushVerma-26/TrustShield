package com.trustshield.fakenews.simhash;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 64-bit SimHash implementation for locality-sensitive hashing and near-duplicate text detection.
 *
 * <p>SimHash projects high-dimensional text feature spaces into a compact 64-bit integer
 * fingerprint such that small lexical variations (e.g. minor typos, reordered punctuation,
 * minor word omissions in viral forwards) produce small Hamming distances.
 *
 * <p>Reference: Charikar, M. S. (2002). Similarity estimation techniques from rounding algorithms.
 * STOC '02.
 */
public final class SimHashMatcher {

    private static final Set<String> STOP_WORDS = new HashSet<>(Arrays.asList(
            "a", "about", "above", "after", "again", "all", "am", "an", "and", "any", "are",
            "as", "at", "be", "because", "been", "before", "being", "below", "between", "both",
            "but", "by", "did", "do", "does", "doing", "down", "during", "each", "few", "for",
            "from", "further", "had", "has", "have", "having", "he", "her", "here", "hers",
            "him", "himself", "his", "how", "i", "if", "in", "into", "is", "it", "its",
            "itself", "just", "me", "more", "most", "my", "myself", "no", "nor", "not",
            "now", "of", "off", "on", "once", "only", "or", "other", "our", "ours", "ourselves",
            "out", "over", "own", "same", "she", "should", "so", "some", "such", "than", "that",
            "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they",
            "this", "those", "through", "to", "too", "under", "until", "up", "very", "was",
            "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why",
            "will", "with", "you", "your", "yours", "yourself", "yourselves"
    ));

    private SimHashMatcher() {
        // Utility class
    }

    /**
     * Computes the 64-bit SimHash fingerprint for the provided text.
     *
     * @param text the input string
     * @return 64-bit long fingerprint (0L if text is empty or lacks alphanumeric content)
     */
    public static long computeHash(String text) {
        if (text == null || text.isBlank()) {
            return 0L;
        }

        List<String> tokens = extractTokens(text);
        if (tokens.isEmpty()) {
            return 0L;
        }

        // Generate multi-scale features:
        // 1. Unigram tokens (weight 2)
        List<Feature> features = new ArrayList<>();
        for (String token : tokens) {
            features.add(new Feature(token, 2));
        }

        // 2. 2-word shingles (bigrams) for word sequence context (weight 1)
        for (int i = 0; i < tokens.size() - 1; i++) {
            String bigram = tokens.get(i) + " " + tokens.get(i + 1);
            features.add(new Feature(bigram, 1));
        }

        // 3. 4-character sliding shingles for inflection, typo, and morphological resilience (weight 1)
        String cleanAlphaNum = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        if (cleanAlphaNum.length() >= 4) {
            for (int i = 0; i <= cleanAlphaNum.length() - 4; i++) {
                features.add(new Feature(cleanAlphaNum.substring(i, i + 4), 1));
            }
        }

        int[] vector = new int[64];
        for (Feature feature : features) {
            long hash = hash64(feature.term);
            for (int i = 0; i < 64; i++) {
                long bitMask = 1L << i;
                if ((hash & bitMask) != 0) {
                    vector[i] += feature.weight;
                } else {
                    vector[i] -= feature.weight;
                }
            }
        }

        long fingerprint = 0L;
        for (int i = 0; i < 64; i++) {
            if (vector[i] > 0) {
                fingerprint |= (1L << i);
            }
        }

        return fingerprint;
    }

    /**
     * Calculates the Hamming distance (number of differing bits) between two 64-bit SimHash values.
     */
    public static int hammingDistance(long hash1, long hash2) {
        return Long.bitCount(hash1 ^ hash2);
    }

    /**
     * Computes the normalized similarity score [0.0, 1.0] between two 64-bit SimHash values.
     * A score of 1.0 indicates identical SimHash fingerprints; 0.0 indicates complete bit inversion.
     */
    public static double similarity(long hash1, long hash2) {
        int distance = hammingDistance(hash1, hash2);
        return 1.0 - ((double) distance / 64.0);
    }

    /**
     * Extracts normalized alphanumeric words excluding common stopwords.
     */
    static List<String> extractTokens(String text) {
        String normalized = text.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9\\s]", " ")
                .trim();

        String[] parts = normalized.split("\\s+");
        List<String> tokens = new ArrayList<>();
        for (String part : parts) {
            if (!part.isBlank() && part.length() > 1 && !STOP_WORDS.contains(part)) {
                tokens.add(part);
            }
        }
        return tokens;
    }

    /**
     * 64-bit FNV-1a hash algorithm for robust bit distribution across all 64 bits.
     */
    static long hash64(String text) {
        long hash = 0xcbf29ce484222325L; // FNV-1a 64-bit offset basis
        for (int i = 0; i < text.length(); i++) {
            hash ^= text.charAt(i);
            hash *= 0x100000001b3L; // FNV-1a 64-bit prime
        }
        return hash;
    }

    private record Feature(String term, int weight) {}
}
