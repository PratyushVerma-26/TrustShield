package com.trustshield.fakenews.style;

import com.trustshield.common.dto.ClaimCheckResponse.StyleAnalysis;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LinguisticStyleAnalyzerTest {

    private LinguisticStyleAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        analyzer = new LinguisticStyleAnalyzer(55);
    }

    @Test
    @DisplayName("Neutral, calm sentence produces low style risk score")
    void neutralTextLowScore() {
        String neutral = "The meteorological department has forecast moderate showers across the coastal regions tomorrow.";
        StyleAnalysis analysis = analyzer.analyze(neutral);

        assertTrue(analysis.styleRiskScore() < 15, "Style risk score should be low: " + analysis.styleRiskScore());
        assertEquals(0, analysis.sensationalPunctuationCount());
        assertTrue(analysis.absolutistTermsFound().isEmpty());
        assertTrue(analysis.unsourcedAttributionPatternsFound().isEmpty());
    }

    @Test
    @DisplayName("High capitalisation shouting increases capitalisation ratio")
    void shoutingText() {
        String shouting = "BREAKING NEWS URGENT NOTICE ALL CITIZENS MUST READ NOW";
        StyleAnalysis analysis = analyzer.analyze(shouting);

        assertTrue(analysis.capitalisationRatio() > 0.80);
        assertTrue(analysis.styleRiskScore() >= 18);
        assertTrue(analysis.absolutistTermsFound().contains("BREAKING"));
        assertTrue(analysis.absolutistTermsFound().contains("URGENT"));
    }

    @Test
    @DisplayName("Sensational punctuation and unsourced attribution patterns are detected")
    void sensationalPunctuationAndUnsourcedAttribution() {
        String text = "Sources confirm that shocking leaked documents prove the secret plan! Officials admit it is true!!";
        StyleAnalysis analysis = analyzer.analyze(text);

        assertTrue(analysis.sensationalPunctuationCount() >= 3);
        assertFalse(analysis.absolutistTermsFound().isEmpty());
        assertFalse(analysis.unsourcedAttributionPatternsFound().isEmpty());
        assertTrue(analysis.styleRiskScore() >= 35);
    }

    @Test
    @DisplayName("Crucial Invariant: Style risk score is strictly capped and can NEVER exceed 55")
    void styleScoreStrictCappingInvariant() {
        // Text constructed to hit every single sensational metric with maximum intensity
        String hyperSensational = "URGENT BREAKING NEWS SHOCKING CONSPIRACY EXPOSED 100% GUARANTEED SECRET MIRACLE CURE " +
                "DELETED BY MEDIA THEY DON'T WANT YOU TO KNOW!!!! " +
                "Sources say and officials admit and insiders reveal that leaked documents prove doctors are baffled!?! " +
                "SHARE BEFORE DELETED VIRAL ALERT MUST WATCH NOW!!!!!";

        StyleAnalysis analysis = analyzer.analyze(hyperSensational);

        // The raw score would easily exceed 80+ if uncapped
        assertEquals(55, analyzer.getMaxStyleScore());
        assertTrue(analysis.styleRiskScore() <= 55,
                "Style risk score must NEVER exceed the configured ceiling of 55: was " + analysis.styleRiskScore());
        assertEquals(55, analysis.styleRiskScore(),
                "Hyper-sensational text should saturate at the 55 ceiling");
    }
}
