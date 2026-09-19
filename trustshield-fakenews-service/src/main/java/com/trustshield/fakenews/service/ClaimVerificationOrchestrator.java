package com.trustshield.fakenews.service;

import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse;
import com.trustshield.common.dto.ClaimCheckResponse.DirectoryFactCheckResult;
import com.trustshield.common.dto.ClaimCheckResponse.FactCheckResult;
import com.trustshield.common.dto.ClaimCheckResponse.SimHashMatch;
import com.trustshield.common.dto.ClaimCheckResponse.StyleAnalysis;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.common.dto.ThreatSignal;
import com.trustshield.fakenews.client.GoogleFactCheckClient;
import com.trustshield.fakenews.directory.InternetFactCheckDirectoryClient;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory.SourceCategory;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory.SourceCredibility;
import com.trustshield.fakenews.multimodal.MultimodalNewsClaimExtractor;
import com.trustshield.fakenews.multimodal.MultimodalNewsClaimExtractor.ExtractedNewsResult;
import com.trustshield.fakenews.multimodal.NewsChyronAnalyzer;
import com.trustshield.fakenews.simhash.DebunkedClaimCatalog;
import com.trustshield.fakenews.style.LinguisticStyleAnalyzer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrator combining multimodal claim extraction, direct fact-checking corroboration,
 * multi-source internet directories, publisher credibility evaluation, offline SimHash near-duplicate
 * matching, and secondary linguistic style analysis.
 *
 * <h2>Evidence Weighting & Invariants</h2>
 * <ol>
 *   <li><strong>Inverted Weighting:</strong> Fact-checking corroboration (Google Fact Check API,
 *       internet ClaimReview directories, or offline SimHash match against debunked claims) is primary direct evidence.
 *       Linguistic style is secondary and only correlates with misinformation.</li>
 *   <li><strong>Source Credibility:</strong> Disinformation networks and satirical outlets (when passed
 *       as real news) provide strong source-level evidence of misinformation.</li>
 *   <li><strong>Visual Chyron Analysis:</strong> Spliced TV news banners and font step discontinuities
 *       provide visual evidence of fabricated broadcast screenshots.</li>
 *   <li><strong>Style Capping:</strong> Style risk score is capped at 55 max and can <em>never</em>
 *       escalate a claim to {@link ThreatLevel#DANGEROUS} (75+) on its own.</li>
 *   <li><strong>The Claim to Refuse:</strong> When no external fact-checking directory is consulted and
 *       no match is found in the offline debunked catalog or source directory, the service returns
 *       {@link ThreatLevel#UNKNOWN}, {@code riskScore = 0}, and {@code degraded = true}. TrustShield
 *       refuses to falsely certify an unindexed claim as clean or true.</li>
 * </ol>
 */
@Service
public class ClaimVerificationOrchestrator {

    private final GoogleFactCheckClient factCheckClient;
    private final DebunkedClaimCatalog claimCatalog;
    private final LinguisticStyleAnalyzer styleAnalyzer;
    private final NewsSourceCredibilityDirectory sourceDirectory;
    private final InternetFactCheckDirectoryClient internetDirectoryClient;
    private final MultimodalNewsClaimExtractor claimExtractor;

    @Autowired
    public ClaimVerificationOrchestrator(
            GoogleFactCheckClient factCheckClient,
            DebunkedClaimCatalog claimCatalog,
            LinguisticStyleAnalyzer styleAnalyzer,
            NewsSourceCredibilityDirectory sourceDirectory,
            InternetFactCheckDirectoryClient internetDirectoryClient,
            MultimodalNewsClaimExtractor claimExtractor) {
        this.factCheckClient = factCheckClient;
        this.claimCatalog = claimCatalog;
        this.styleAnalyzer = styleAnalyzer;
        this.sourceDirectory = sourceDirectory;
        this.internetDirectoryClient = internetDirectoryClient;
        this.claimExtractor = claimExtractor;
    }

    /**
     * Backwards-compatible 3-argument constructor for legacy callers and unit tests.
     */
    public ClaimVerificationOrchestrator(
            GoogleFactCheckClient factCheckClient,
            DebunkedClaimCatalog claimCatalog,
            LinguisticStyleAnalyzer styleAnalyzer) {
        this(
                factCheckClient,
                claimCatalog,
                styleAnalyzer,
                new NewsSourceCredibilityDirectory(),
                new InternetFactCheckDirectoryClient(false, "", 3000),
                new MultimodalNewsClaimExtractor(
                        new NewsChyronAnalyzer(0.65),
                        new NewsSourceCredibilityDirectory()
                )
        );
    }

    /**
     * Executes end-to-end multimodal claim verification, directory corroboration, and style analysis.
     */
    public ClaimCheckResponse verifyClaim(ClaimCheckRequest request) {
        long startMs = System.currentTimeMillis();
        IncidentId incidentId = request.incidentId() != null ? request.incidentId() : IncidentId.generate();

        // 1. Multimodal Extraction: extracts text claims and chyron features from image/video news
        ExtractedNewsResult extraction = claimExtractor.extractClaim(request);
        String effectiveClaimText = extraction.effectiveClaimText();

        // 2. Source Credibility: evaluates publisher domain / outlet if detected
        SourceCredibility sourceCred = sourceDirectory.evaluateSource(
                extraction.detectedSourceDomain() != null ? extraction.detectedSourceDomain() : effectiveClaimText
        );

        // 3. Primary: Query Google Fact Check Tools API
        FactCheckResult factCheck = factCheckClient.searchClaim(effectiveClaimText);

        // 4. Primary: Offline SimHash near-duplicate search against bundled debunked claims
        SimHashMatch simHashMatch = claimCatalog.findBestMatch(effectiveClaimText);

        // 5. Primary: Multi-source Internet Fact-Checking Directory
        DirectoryFactCheckResult directoryResult = internetDirectoryClient.queryDirectories(effectiveClaimText);

        // 6. Secondary: Linguistic style analysis (capitalisation, punctuation, absolutist terms)
        StyleAnalysis styleAnalysis = styleAnalyzer.analyze(effectiveClaimText);

        long latencyMs = System.currentTimeMillis() - startMs;

        // 7. Derive module verdict enforcing all core invariants
        ModuleVerdict verdict = deriveVerdict(
                factCheck,
                simHashMatch,
                directoryResult,
                sourceCred,
                extraction,
                styleAnalysis,
                latencyMs
        );

        return new ClaimCheckResponse(
                incidentId,
                effectiveClaimText,
                verdict,
                factCheck,
                simHashMatch,
                styleAnalysis,
                extraction.extraction(),
                directoryResult
        );
    }

    private ModuleVerdict deriveVerdict(
            FactCheckResult factCheck,
            SimHashMatch simHashMatch,
            DirectoryFactCheckResult directoryResult,
            SourceCredibility sourceCred,
            ExtractedNewsResult extraction,
            StyleAnalysis styleAnalysis,
            long latencyMs) {

        List<ThreatSignal> signals = new ArrayList<>();

        // Add style signals
        if (styleAnalysis.capitalisationRatio() >= 0.25) {
            signals.add(ThreatSignal.triggered(
                    "CAPITALISATION_SHOUTING",
                    String.format("High uppercase letter ratio (%.0f%%)", styleAnalysis.capitalisationRatio() * 100),
                    styleAnalysis.capitalisationRatio() >= 0.50 ? 18 : 10,
                    "STYLE_ANALYSIS"
            ));
        }

        if (styleAnalysis.sensationalPunctuationCount() > 0) {
            signals.add(ThreatSignal.triggered(
                    "SENSATIONAL_PUNCTUATION",
                    "Contains " + styleAnalysis.sensationalPunctuationCount() + " sensational punctuation marks (! or ?)",
                    Math.min(16, styleAnalysis.sensationalPunctuationCount() * 4),
                    "STYLE_ANALYSIS"
            ));
        }

        if (!styleAnalysis.absolutistTermsFound().isEmpty()) {
            signals.add(ThreatSignal.triggered(
                    "ABSOLUTIST_TERMS",
                    "Contains sensationalist/absolutist vocabulary: " + String.join(", ", styleAnalysis.absolutistTermsFound()),
                    Math.min(24, styleAnalysis.absolutistTermsFound().size() * 8),
                    "STYLE_ANALYSIS"
            ));
        }

        if (!styleAnalysis.unsourcedAttributionPatternsFound().isEmpty()) {
            signals.add(ThreatSignal.triggered(
                    "UNSOURCED_ATTRIBUTION",
                    "Contains unsourced attribution patterns: " + String.join(", ", styleAnalysis.unsourcedAttributionPatternsFound()),
                    Math.min(24, styleAnalysis.unsourcedAttributionPatternsFound().size() * 12),
                    "STYLE_ANALYSIS"
            ));
        }

        // Add visual chyron signals if media was analyzed
        if (extraction.chyronAnalysis().chyronDetected()) {
            if (extraction.chyronAnalysis().splicedOrManipulated()) {
                signals.add(ThreatSignal.triggered(
                        "CHYRON_SPLICED_MANIPULATION",
                        "Television news chyron exhibits font step discontinuity or splice tampering: " +
                                String.join("; ", extraction.chyronAnalysis().anomalies()),
                        35,
                        "CHYRON_ANALYSIS"
                ));
            } else {
                signals.add(ThreatSignal.passed(
                        "BROADCAST_CHYRON_LAYOUT",
                        "Detected television broadcast lower-third layout (" + extraction.chyronAnalysis().bannerType() + ")",
                        "CHYRON_ANALYSIS"
                ));
            }
        }

        // Add source credibility signals
        if (sourceCred.isKnownSource()) {
            switch (sourceCred.category()) {
                case KNOWN_MISINFO_PROPAGANDA -> signals.add(ThreatSignal.triggered(
                        "KNOWN_DISINFORMATION_OUTLET",
                        "Originates from known disinformation/propaganda domain: " + sourceCred.name() + " (" + sourceCred.domain() + ")",
                        sourceCred.riskScore(),
                        "SOURCE_CREDIBILITY"
                ));
                case SATIRE_PARODY -> signals.add(ThreatSignal.triggered(
                        "SATIRE_OUTLET_DETECTED",
                        "Content originates from recognized satire/parody publisher: " + sourceCred.name() + ". Misinformation risk if interpreted literally.",
                        85,
                        "SOURCE_CREDIBILITY"
                ));
                case TRUSTED_MAINSTREAM -> signals.add(ThreatSignal.passed(
                        "ESTABLISHED_NEWS_SOURCE",
                        "Published by reputable journalistic organisation: " + sourceCred.name() + " (" + sourceCred.domain() + ")",
                        "SOURCE_CREDIBILITY"
                ));
                default -> {}
            }
        }

        // CASE 1: External Fact Check API confirmed a debunked match
        if (factCheck != null && factCheck.matchFound()) {
            int score = Math.max(90, Math.min(98, 90 + (styleAnalysis.styleRiskScore() / 10)));
            String publisher = factCheck.publisher() != null ? factCheck.publisher() : "Fact Checker";
            String rating = factCheck.textualRating() != null ? factCheck.textualRating() : "Debunked";
            String title = factCheck.reviewTitle() != null ? factCheck.reviewTitle() : "Claim Review";

            signals.add(ThreatSignal.triggered(
                    "FACT_CHECK_CORROBORATION",
                    "Debunked by " + publisher + " with rating '" + rating + "': " + title,
                    90,
                    "GOOGLE_FACT_CHECK"
            ));

            String explanation = String.format(
                    "Claim matches a verified debunked claim reviewed by %s with rating '%s'. Title: %s",
                    publisher, rating, title
            );

            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "FACT_CHECK_CORROBORATION",
                    explanation,
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 2: Offline SimHash near-duplicate match against bundled debunked catalog
        if (simHashMatch != null && simHashMatch.matched()) {
            int baseScore = (int) Math.round(simHashMatch.similarity() * 95.0);
            int score = Math.max(85, Math.min(96, baseScore));
            String source = simHashMatch.debunkSourceUrl() != null ? simHashMatch.debunkSourceUrl() : "Fact Check Agency";

            signals.add(ThreatSignal.triggered(
                    "SIMHASH_NEAR_DUPLICATE_DEBUNKED",
                    String.format("Matches known debunked hoax with %d%% similarity (source: %s)",
                            (int) (simHashMatch.similarity() * 100), source),
                    score,
                    "OFFLINE_SIMHASH"
            ));

            String explanation = String.format(
                    "Claim matches previously debunked misinformation with %d%% textual similarity. Debunk source: %s",
                    (int) (simHashMatch.similarity() * 100), source
            );

            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "SIMHASH_NEAR_DUPLICATE_DEBUNKED",
                    explanation,
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 3: Multi-Source Internet Fact-Checking Directory matched
        if (directoryResult != null && directoryResult.matchFound()) {
            int score = 92;
            signals.add(ThreatSignal.triggered(
                    "INTERNET_DIRECTORY_DEBUNKED",
                    String.format("Debunked in internet directory by %s (%s): %s",
                            directoryResult.sourceName(), directoryResult.textualRating(), directoryResult.verifiedClaim()),
                    score,
                    "INTERNET_DIRECTORY"
            ));

            String explanation = String.format(
                    "Claim matches verified debunk in internet fact-checking directory by %s with rating '%s'. Source: %s",
                    directoryResult.sourceName(), directoryResult.textualRating(), directoryResult.reviewUrl()
            );

            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "INTERNET_DIRECTORY_DEBUNKED",
                    explanation,
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 4: Known Disinformation / Propaganda Outlet Source
        if (sourceCred.category() == SourceCategory.KNOWN_MISINFO_PROPAGANDA) {
            int score = Math.max(90, sourceCred.riskScore());
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "DISINFORMATION_PROPAGANDA_OUTLET",
                    "Claim originates from documented disinformation/propaganda outlet: " + sourceCred.name() + ". " + sourceCred.rationale(),
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 5: Satire / Parody Publisher
        if (sourceCred.category() == SourceCategory.SATIRE_PARODY) {
            int score = 85;
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "SATIRICAL_NEWS_CONTENT",
                    "Claim is fabricated humor or parody from " + sourceCred.name() + ". High risk when presented as factual news.",
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 6: Spliced / Fabricated Television News Chyron
        if (extraction.chyronAnalysis().splicedOrManipulated()) {
            int score = Math.min(88, 70 + (styleAnalysis.styleRiskScore() / 4));
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.DANGEROUS,
                    "FABRICATED_CHYRON_HOAX",
                    "Visual forensics identified spliced television news chyron typography with font step discontinuities.",
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 7: Reputable Mainstream Source (with clean forensics and no debunks)
        if (sourceCred.category() == SourceCategory.TRUSTED_MAINSTREAM) {
            int score = Math.min(25, Math.max(5, styleAnalysis.styleRiskScore() / 3));
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    score,
                    ThreatLevel.fromScore(score),
                    "VERIFIED_REPUTABLE_SOURCE",
                    "Reported by established journalistic agency " + sourceCred.name() + " (" + sourceCred.domain() + ") with no debunk records.",
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        // CASE 8: No direct corroboration from Fact Check API, SimHash Catalog, or Internet Directories
        boolean factCheckConsulted = (factCheck != null && factCheck.consulted()) || (directoryResult != null && directoryResult.consulted());

        if (!factCheckConsulted) {
            signals.add(ThreatSignal.passed(
                    "FACT_CHECK_UNAVAILABLE",
                    "External fact-checking API is disabled or unconfigured",
                    "GOOGLE_FACT_CHECK"
            ));

            if (styleAnalysis.styleRiskScore() >= 40) {
                // Noticeable sensationalism, but uncorroborated: cap at SUSPICIOUS and mark degraded
                return new ModuleVerdict(
                        ModuleType.FAKENEWS,
                        styleAnalysis.styleRiskScore(),
                        ThreatLevel.SUSPICIOUS,
                        "SENSATIONALIST_STYLE_CORRELATION",
                        "Sensationalist style patterns detected, but external fact-checking APIs are unconfigured or unreachable.",
                        signals,
                        latencyMs,
                        Instant.now(),
                        true
                );
            }

            // Low sensationalism and zero external fact check sources reached:
            // Crucial invariant: Refuse to claim SAFE when nothing was checked!
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    0,
                    ThreatLevel.UNKNOWN,
                    "NO_SOURCES_CONSULTED",
                    "External fact-checking API is disabled and claim is not indexed in offline debunked catalog. Cannot verify factual veracity.",
                    signals,
                    latencyMs,
                    Instant.now(),
                    true
            );
        }

        // CASE 9: Fact Check API was consulted and returned no matches
        signals.add(ThreatSignal.passed(
                "NO_FACT_CHECK_RECORD",
                "No debunking records found in fact-checking database",
                "GOOGLE_FACT_CHECK"
        ));

        if (styleAnalysis.styleRiskScore() >= 40) {
            return new ModuleVerdict(
                    ModuleType.FAKENEWS,
                    styleAnalysis.styleRiskScore(),
                    ThreatLevel.SUSPICIOUS,
                    "SENSATIONALIST_STYLE_CORRELATION",
                    "No fact-check debunks found in public databases, but claim exhibits high sensationalism or unsourced attribution.",
                    signals,
                    latencyMs,
                    Instant.now(),
                    false
            );
        }

        int score = Math.max(5, styleAnalysis.styleRiskScore());
        ThreatLevel level = ThreatLevel.fromScore(score); // LOW or SAFE
        return new ModuleVerdict(
                ModuleType.FAKENEWS,
                score,
                level,
                "NO_FACT_CHECK_CONCERNS",
                "No debunked records found for this claim in fact-checking databases, and linguistic style displays low sensationalism.",
                signals,
                latencyMs,
                Instant.now(),
                false
        );
    }
}
