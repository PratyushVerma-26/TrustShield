package com.trustshield.fakenews.style;

import com.trustshield.common.dto.ClaimCheckResponse.StyleAnalysis;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secondary linguistic style analyzer.
 *
 * <p>Examines textual sensationalism, urgency manipulation, and unsourced attribution patterns:
 * <ul>
 *   <li>Capitalisation ratio (uppercase shouting frequency)</li>
 *   <li>Sensational punctuation density (!, ?, !?, !!!)</li>
 *   <li>Absolutist and conspiracy vocabulary</li>
 *   <li>Vague or unsourced authority attributions ("sources confirm", "forwarded as received")</li>
 * </ul>
 *
 * <p><strong>Core Invariant:</strong>
 * Linguistic style is secondary evidence that only correlates with misinformation; it is not direct
 * evidence of falsehood. Therefore, {@code styleRiskScore} is hard-capped at {@code maxStyleScore}
 * (default 55) and can <em>never</em> reach {@code ThreatLevel.DANGEROUS} (75+) on its own.
 */
@Component
public class LinguisticStyleAnalyzer {

    public static final int DEFAULT_MAX_STYLE_SCORE = 55;

    private static final List<String> ABSOLUTIST_TERMS = List.of(
            "shocking", "urgent", "breaking", "miracle", "secret", "exposed",
            "banned", "conspiracy", "guaranteed", "deleted by media", "they don't want you to know",
            "won't tell you", "share before deleted", "must watch", "cure for all", "100%",
            "undeniable proof", "viral alert", "suppressed truth", "hidden agenda"
    );

    private static final List<Pattern> UNSOURCED_PATTERNS = List.of(
            Pattern.compile("\\bsources? (?:say|confirms?|reveal|claims?)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bofficials? (?:admit|reveal|confirms?|say)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\binsiders? (?:claims?|reveal|warns?)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\banonymous sources?\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bforwarded as received\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bexperts (?:warn|admit|agree that)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bleaked documents? (?:show|prove|reveal)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bdoctors (?:are baffled|finally admit|warn)\\b", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\bscientists (?:confirm|finally admit)\\b", Pattern.CASE_INSENSITIVE)
    );

    private static final Pattern SENSATIONAL_PUNCTUATION = Pattern.compile("[!?]{1,}");

    private final int maxStyleScore;

    public LinguisticStyleAnalyzer(
            @Value("${trustshield.fakenews.style.max-style-score:55}") int maxStyleScore) {
        this.maxStyleScore = maxStyleScore;
    }

    public LinguisticStyleAnalyzer() {
        this(DEFAULT_MAX_STYLE_SCORE);
    }

    /**
     * Performs linguistic style analysis on the claim text.
     *
     * @param text the claim string
     * @return StyleAnalysis containing the individual markers and the capped style risk score
     */
    public StyleAnalysis analyze(String text) {
        if (text == null || text.isBlank()) {
            return new StyleAnalysis(0.0, 0, Collections.emptyList(), Collections.emptyList(), 0);
        }

        double capRatio = computeCapitalisationRatio(text);
        int punctCount = countSensationalPunctuation(text);
        List<String> absolutistTerms = findAbsolutistTerms(text);
        List<String> unsourcedAttributions = findUnsourcedAttributions(text);

        int rawScore = 0;

        // 1. Capitalisation contribution (up to 18 points)
        if (capRatio >= 0.50) {
            rawScore += 18;
        } else if (capRatio >= 0.25) {
            rawScore += 10;
        } else if (capRatio >= 0.15) {
            rawScore += 5;
        }

        // 2. Sensational punctuation contribution (up to 16 points)
        rawScore += Math.min(16, punctCount * 4);

        // 3. Absolutist & sensational vocabulary (up to 24 points)
        rawScore += Math.min(24, absolutistTerms.size() * 8);

        // 4. Unsourced attribution patterns (up to 24 points)
        rawScore += Math.min(24, unsourcedAttributions.size() * 12);

        // Enforce the strict ceiling invariant
        int finalScore = Math.min(this.maxStyleScore, rawScore);

        return new StyleAnalysis(
                Math.round(capRatio * 100.0) / 100.0,
                punctCount,
                absolutistTerms,
                unsourcedAttributions,
                finalScore
        );
    }

    private double computeCapitalisationRatio(String text) {
        int uppercaseCount = 0;
        int totalLetters = 0;

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isLetter(c)) {
                totalLetters++;
                if (Character.isUpperCase(c)) {
                    uppercaseCount++;
                }
            }
        }

        if (totalLetters < 5) {
            return 0.0;
        }

        return (double) uppercaseCount / (double) totalLetters;
    }

    private int countSensationalPunctuation(String text) {
        Matcher matcher = SENSATIONAL_PUNCTUATION.matcher(text);
        int count = 0;
        while (matcher.find()) {
            String match = matcher.group();
            // Single punctuation or clusters like '!!', '???', '!?!'
            if (match.length() > 1 || match.equals("!")) {
                count += match.length();
            }
        }
        return count;
    }

    private List<String> findAbsolutistTerms(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        List<String> matches = new ArrayList<>();
        for (String term : ABSOLUTIST_TERMS) {
            if (lower.contains(term)) {
                matches.add(term.toUpperCase(Locale.ROOT));
            }
        }
        return matches;
    }

    private List<String> findUnsourcedAttributions(String text) {
        List<String> matches = new ArrayList<>();
        for (Pattern pattern : UNSOURCED_PATTERNS) {
            Matcher matcher = pattern.matcher(text);
            if (matcher.find()) {
                matches.add(matcher.group());
            }
        }
        return matches;
    }

    public int getMaxStyleScore() {
        return maxStyleScore;
    }
}
