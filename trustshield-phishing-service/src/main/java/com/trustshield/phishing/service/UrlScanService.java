package com.trustshield.phishing.service;

import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.common.dto.ThreatSignal;
import com.trustshield.common.util.HashUtils;
import com.trustshield.phishing.dto.ScanHistoryItem;
import com.trustshield.phishing.dto.ScanRequest;
import com.trustshield.phishing.dto.ScanResponse;
import com.trustshield.phishing.entity.ScanRecord;
import com.trustshield.phishing.ml.ModelPrediction;
import com.trustshield.phishing.ml.PhishingModel;
import com.trustshield.phishing.ml.UrlFeatureExtractor;
import com.trustshield.phishing.repository.ScanRecordRepository;
import com.trustshield.phishing.reputation.ReputationSource;
import com.trustshield.phishing.reputation.ReputationVerdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Orchestrates real-time phishing threat evaluation.
 *
 * <p>Employs a two-tier evaluation architecture:
 * <ol>
 *   <li><b>Lexical Machine Learning:</b> The 26-feature calibrated logistic regression model
 *       serves as the primary real-time classifier, identifying zero-day threats.</li>
 *   <li><b>Reputation Corroboration:</b> External threat intelligence sources (Google Safe Browsing,
 *       VirusTotal) execute asynchronously. Confirmed reputation hits escalate the risk score
 *       above the threat floor, preserving the raise-only safety invariant.</li>
 * </ol>
 *
 * <p>External queries run concurrently with strict execution timeouts. On upstream timeout or
 * failure, the local ML verdict is returned with {@code degraded=true} to protect SLA budgets.
 */
@Service
public class UrlScanService {

    private static final Logger log = LoggerFactory.getLogger(UrlScanService.class);

    /** Minimum |logit| contribution for a feature to be worth showing a user. */
    private static final double SIGNAL_THRESHOLD = 0.05;

    /** How many lexical features to surface as evidence. */
    private static final int MAX_LEXICAL_SIGNALS = 5;

    private final PhishingModel model;
    private final List<ReputationSource> reputationSources;
    private final ScanRecordRepository repository;

    @Value("${trustshield.phishing.blacklist-confirmed-floor:90}")
    private int blacklistConfirmedFloor;

    @Value("${trustshield.phishing.enrichment-timeout-ms:1200}")
    private long enrichmentTimeoutMs;

    public UrlScanService(PhishingModel model,
                          List<ReputationSource> reputationSources,
                          ScanRecordRepository repository) {
        this.model = model;
        this.reputationSources = reputationSources;
        this.repository = repository;
    }

    @Transactional
    public ScanResponse scan(ScanRequest request) {
        long startNanos = System.nanoTime();
        String url = request.url().trim();

        // ---- 1. Primary signal: the local lexical classifier -----------------
        ModelPrediction prediction = model.predict(url);
        int score = prediction.riskScore();

        List<ThreatSignal> signals = new ArrayList<>(lexicalSignals(prediction, score));

        // ---- 2. Corroboration: external reputation, raise-only ---------------
        List<ReputationVerdict> reputation = consultReputationSources(url);
        boolean degraded = !model.isTrained();

        for (ReputationVerdict rv : reputation) {
            if (!rv.available()) {
                signals.add(ThreatSignal.passed(
                        rv.source() + "_UNAVAILABLE",
                        "Could not consult " + friendly(rv.source()) + ": " + rv.detail(),
                        rv.source()));
                // Only a source that was switched on and then failed degrades the
                // verdict. A source with no key configured was never expected to
                // answer, so it is not a degradation.
                if (isEnabled(rv.source())) {
                    degraded = true;
                }
                continue;
            }
            if (rv.flagged()) {
                int before = score;
                score = Math.max(score, blacklistConfirmedFloor);
                signals.add(ThreatSignal.triggered(
                        rv.source() + "_MATCH",
                        friendly(rv.source()) + " lists this address as malicious. " + rv.detail(),
                        Math.max(0, score - before),
                        rv.source()));
            } else {
                // Recorded as a check that passed, contributing zero. Deliberately
                // not a mitigating signal: see the class comment.
                signals.add(ThreatSignal.passed(
                        rv.source() + "_NO_MATCH",
                        "Not currently listed by " + friendly(rv.source())
                                + " (blocklists lag new phishing sites, so this is not proof of safety)",
                        rv.source()));
            }
        }

        // ---- 3. Assemble the verdict -----------------------------------------
        ThreatLevel level = ThreatLevel.fromScore(score);
        String verdictCode = verdictCode(level);
        String explanation = buildExplanation(level, signals, degraded);
        long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);

        ModuleVerdict verdict = degraded
                ? ModuleVerdict.degraded(ModuleType.PHISHING, score, verdictCode, explanation, signals, latencyMs)
                : ModuleVerdict.of(ModuleType.PHISHING, score, verdictCode, explanation, signals, latencyMs);

        // ---- 4. Persist for history and for the fusion service ---------------
        ScanRecord saved = repository.save(new ScanRecord(
                url,
                HashUtils.sha256Hex(url),
                hostOf(url),
                score,
                level,
                verdictCode,
                truncate(explanation, 1024),
                latencyMs,
                degraded,
                model.getModelVersion(),
                model.getProvenance(),
                request.context() == null ? null : request.context().toUpperCase(Locale.ROOT),
                Instant.now()));

        return new ScanResponse(
                saved.getId(),
                url,
                verdict,
                new ScanResponse.ModelInfo(
                        model.getModelVersion(),
                        model.getProvenance(),
                        model.isTrained(),
                        prediction.probability(),
                        prediction.logit()),
                reputation,
                topFeatures(prediction));
    }

    @Transactional(readOnly = true)
    public List<ScanHistoryItem> recentScans() {
        return repository.findTop25ByOrderByScannedAtDesc().stream()
                .map(r -> new ScanHistoryItem(
                        r.getId(), r.getUrl(), r.getRiskScore(), r.getThreatLevel(),
                        r.getVerdict(), r.getLatencyMs(), r.isDegraded(), r.getScannedAt()))
                .toList();
    }

    @Transactional(readOnly = true)
    public long countDangerous() {
        return repository.countByRiskScoreGreaterThanEqual(75);
    }

    @Transactional(readOnly = true)
    public long totalScans() {
        return repository.count();
    }

    // ------------------------------------------------------------------------
    // Explainability
    // ------------------------------------------------------------------------

    /**
     * Converts per-feature logit contributions into user-facing signals.
     *
     * <p>The points attributed to each signal are that feature's share of the
     * total positive evidence, scaled to the final score. This is a presentation
     * choice and is stated as such: the underlying attribution {@code w_i * z_i}
     * is exact for a linear model, but log-odds are not points, so the two cannot
     * be equated without a scaling convention. Sharing out the score in proportion
     * to positive contribution is the convention used here, and it has the
     * property that the displayed points sum to the score.
     */
    private List<ThreatSignal> lexicalSignals(ModelPrediction prediction, int score) {
        double[] contributions = prediction.contributions();
        double[] standardised = prediction.features();

        double positiveMass = 0.0;
        for (double c : contributions) {
            if (c > 0) {
                positiveMass += c;
            }
        }

        List<Integer> byImpact = new ArrayList<>();
        for (int i = 0; i < contributions.length; i++) {
            byImpact.add(i);
        }
        byImpact.sort(Comparator.comparingDouble((Integer i) -> contributions[i]).reversed());

        List<ThreatSignal> signals = new ArrayList<>();

        for (int idx : byImpact) {
            if (signals.size() >= MAX_LEXICAL_SIGNALS) {
                break;
            }
            double c = contributions[idx];
            if (c <= SIGNAL_THRESHOLD) {
                break;
            }
            int points = positiveMass > 0 ? (int) Math.round(score * (c / positiveMass)) : 0;
            signals.add(ThreatSignal.triggered(
                    UrlFeatureExtractor.FEATURE_NAMES[idx].toUpperCase(Locale.ROOT),
                    UrlFeatureExtractor.FEATURE_DESCRIPTIONS[idx],
                    points,
                    "LEXICAL_MODEL"));
        }

        // Surface the single strongest reason to be less suspicious, if any. HTTPS
        // is the usual one. Shown so the explanation does not read as one-sided.
        int mostNegative = byImpact.get(byImpact.size() - 1);
        if (contributions[mostNegative] < -SIGNAL_THRESHOLD) {
            signals.add(ThreatSignal.mitigating(
                    UrlFeatureExtractor.FEATURE_NAMES[mostNegative].toUpperCase(Locale.ROOT),
                    UrlFeatureExtractor.FEATURE_DESCRIPTIONS[mostNegative],
                    (int) Math.round(Math.abs(contributions[mostNegative]) * 5),
                    "LEXICAL_MODEL"));
        }

        if (signals.isEmpty()) {
            signals.add(ThreatSignal.passed(
                    "LEXICAL_ANALYSIS",
                    "No unusual patterns found in the structure of this web address",
                    "LEXICAL_MODEL"));
        }

        // Keep the raw z-score around in the log for debugging odd verdicts.
        if (log.isDebugEnabled()) {
            log.debug("logit={} probability={} strongest={} z={}",
                    prediction.logit(), prediction.probability(),
                    UrlFeatureExtractor.FEATURE_NAMES[byImpact.get(0)],
                    standardised[byImpact.get(0)]);
        }

        return signals;
    }

    private List<ScanResponse.FeatureAttribution> topFeatures(ModelPrediction prediction) {
        double[] contributions = prediction.contributions();
        double[] standardised = prediction.features();

        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < contributions.length; i++) {
            indices.add(i);
        }
        // Rank by magnitude so both risk-raising and risk-reducing features appear.
        indices.sort(Comparator.comparingDouble((Integer i) -> Math.abs(contributions[i])).reversed());

        List<ScanResponse.FeatureAttribution> out = new ArrayList<>();
        for (int i = 0; i < Math.min(8, indices.size()); i++) {
            int idx = indices.get(i);
            out.add(new ScanResponse.FeatureAttribution(
                    UrlFeatureExtractor.FEATURE_NAMES[idx],
                    UrlFeatureExtractor.FEATURE_DESCRIPTIONS[idx],
                    round4(standardised[idx]),
                    round4(contributions[idx])));
        }
        return out;
    }

    private String buildExplanation(ThreatLevel level, List<ThreatSignal> signals, boolean degraded) {
        List<ThreatSignal> fired = signals.stream()
                .filter(s -> s.triggered() && s.contribution() > 0)
                .sorted(Comparator.comparingInt(ThreatSignal::contribution).reversed())
                .limit(2)
                .toList();

        StringBuilder sb = new StringBuilder();
        sb.append(level.getRecommendation());

        if (!fired.isEmpty()) {
            sb.append(" Main reasons: ");
            for (int i = 0; i < fired.size(); i++) {
                if (i > 0) {
                    sb.append("; ");
                }
                sb.append(lowerFirst(fired.get(i).description()));
            }
            sb.append('.');
        }

        if (degraded) {
            sb.append(" This assessment is marked provisional");
            if (!model.isTrained()) {
                sb.append(" because the classifier is running on untrained bootstrap weights");
            }
            sb.append('.');
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------------
    // External sources
    // ------------------------------------------------------------------------

    /**
     * Queries every enabled reputation source concurrently, abandoning any that
     * exceed the shared timeout budget.
     *
     * <p>Uses one virtual thread per lookup (Java 21). These tasks are pure I/O
     * wait, which is exactly the workload virtual threads exist for: no pool
     * sizing to tune, and blocking a virtual thread on a socket does not pin a
     * platform thread.
     */
    private List<ReputationVerdict> consultReputationSources(String url) {
        List<ReputationSource> enabled = reputationSources.stream()
                .filter(ReputationSource::isEnabled)
                .toList();

        // Fast path, and the default configuration: nothing enabled means no
        // executor, no sockets, and no added latency.
        if (enabled.isEmpty()) {
            return reputationSources.stream()
                    .map(s -> ReputationVerdict.unavailable(s.name(), "Source not enabled"))
                    .toList();
        }

        List<ReputationVerdict> results = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<ReputationVerdict>> tasks = enabled.stream()
                    .map(s -> (Callable<ReputationVerdict>) () -> s.check(url))
                    .toList();

            List<Future<ReputationVerdict>> futures =
                    pool.invokeAll(tasks, enrichmentTimeoutMs, TimeUnit.MILLISECONDS);

            for (int i = 0; i < futures.size(); i++) {
                String name = enabled.get(i).name();
                try {
                    results.add(futures.get(i).get());
                } catch (CancellationException e) {
                    results.add(ReputationVerdict.unavailable(
                            name, "Timed out after " + enrichmentTimeoutMs + " ms"));
                } catch (Exception e) {
                    results.add(ReputationVerdict.unavailable(
                            name, "Failed: " + e.getClass().getSimpleName()));
                }
            }
            pool.shutdownNow();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return enabled.stream()
                    .map(s -> ReputationVerdict.unavailable(s.name(), "Interrupted"))
                    .toList();
        }

        // Report disabled sources too, so the response shows everything that was
        // and was not consulted.
        reputationSources.stream()
                .filter(s -> !s.isEnabled())
                .forEach(s -> results.add(
                        ReputationVerdict.unavailable(s.name(), "Source not enabled")));

        return results;
    }

    private boolean isEnabled(String sourceName) {
        return reputationSources.stream()
                .anyMatch(s -> s.name().equals(sourceName) && s.isEnabled());
    }

    // ------------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------------

    /**
     * Maps a severity band onto this module's machine-readable outcome code.
     *
     * <p>Exhaustive mapping ensures any added {@link ThreatLevel} constants require
     * explicit handling here. {@code UNKNOWN} provides a safe fallback mapping.
     */
    private static String verdictCode(ThreatLevel level) {
        return switch (level) {
            case DANGEROUS -> "PHISHING_DETECTED";
            case SUSPICIOUS -> "LIKELY_PHISHING";
            case LOW -> "MINOR_ANOMALIES";
            case SAFE -> "NO_THREAT_DETECTED";
            case UNKNOWN -> "NOT_ASSESSED";
        };
    }

    private static String friendly(String sourceName) {
        return switch (sourceName) {
            case "GOOGLE_SAFE_BROWSING" -> "Google Safe Browsing";
            case "VIRUSTOTAL" -> "VirusTotal";
            default -> sourceName;
        };
    }

    private static String hostOf(String url) {
        try {
            String lower = url.toLowerCase(Locale.ROOT);
            String withScheme = lower.startsWith("http://") || lower.startsWith("https://")
                    ? url : "http://" + url;
            String host = new URI(withScheme).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }

    private static String lowerFirst(String s) {
        return (s == null || s.isEmpty())
                ? s
                : Character.toLowerCase(s.charAt(0)) + s.substring(1);
    }

    private static String truncate(String s, int max) {
        return (s == null || s.length() <= max) ? s : s.substring(0, max);
    }

    private static double round4(double v) {
        return Math.round(v * 10_000.0) / 10_000.0;
    }
}
