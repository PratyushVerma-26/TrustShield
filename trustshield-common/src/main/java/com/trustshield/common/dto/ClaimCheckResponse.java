package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Verification outcome for a claim or news item across text, image, and video modalities.
 *
 * <p>Separates corroborated evidence (Google Fact Check Tools API / open directory ClaimReview /
 * SimHash near-duplicate matching against debunked claims) from linguistic style correlation and
 * multimodal headline extraction from news banners/tickers.
 *
 * @param incidentId correlation identifier
 * @param claimText original claim evaluated
 * @param verdict uniform module verdict
 * @param factCheck direct corroboration results (e.g. from Google Fact Check API)
 * @param simHashMatch offline near-duplicate hit from bundled debunked claims
 * @param styleAnalysis linguistic style markers
 * @param multimodalExtraction extracted headlines and news chyron features from image/video
 * @param directoryResult multi-source internet fact-checking directory results
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimCheckResponse(
        IncidentId incidentId,
        String claimText,
        ModuleVerdict verdict,
        FactCheckResult factCheck,
        SimHashMatch simHashMatch,
        StyleAnalysis styleAnalysis,
        MultimodalExtraction multimodalExtraction,
        DirectoryFactCheckResult directoryResult
) {
    public ClaimCheckResponse(
            IncidentId incidentId,
            String claimText,
            ModuleVerdict verdict,
            FactCheckResult factCheck,
            SimHashMatch simHashMatch,
            StyleAnalysis styleAnalysis
    ) {
        this(incidentId, claimText, verdict, factCheck, simHashMatch, styleAnalysis, MultimodalExtraction.none(), DirectoryFactCheckResult.unavailable());
    }

    public ClaimCheckResponse {
        multimodalExtraction = multimodalExtraction != null ? multimodalExtraction : MultimodalExtraction.none();
        directoryResult = directoryResult != null ? directoryResult : DirectoryFactCheckResult.unavailable();
    }

    public record FactCheckResult(
            boolean consulted,
            boolean matchFound,
            String claimant,
            String reviewTitle,
            String reviewUrl,
            String textualRating,
            String publisher
    ) {
        public static FactCheckResult unavailable() {
            return new FactCheckResult(false, false, null, null, null, null, null);
        }
    }

    public record SimHashMatch(
            boolean matched,
            String matchedClaim,
            double similarity,
            String debunkSourceUrl
    ) {
        public static SimHashMatch none() {
            return new SimHashMatch(false, null, 0.0, null);
        }
    }

    public record StyleAnalysis(
            double capitalisationRatio,
            int sensationalPunctuationCount,
            List<String> absolutistTermsFound,
            List<String> unsourcedAttributionPatternsFound,
            int styleRiskScore
    ) {}

    public record MultimodalExtraction(
            boolean mediaProcessed,
            String mediaType,
            String extractedHeadline,
            boolean chyronDetected,
            String detectedSourceDomain,
            double textConfidence
    ) {
        public static MultimodalExtraction none() {
            return new MultimodalExtraction(false, "TEXT", null, false, null, 1.0);
        }
    }

    public record DirectoryFactCheckResult(
            boolean consulted,
            boolean matchFound,
            String sourceName,
            String textualRating,
            String reviewUrl,
            String verifiedClaim
    ) {
        public static DirectoryFactCheckResult unavailable() {
            return new DirectoryFactCheckResult(false, false, null, null, null, null);
        }
    }
}
