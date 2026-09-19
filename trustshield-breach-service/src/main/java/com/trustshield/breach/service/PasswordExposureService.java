package com.trustshield.breach.service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.trustshield.breach.config.BreachProperties;
import com.trustshield.breach.dto.PasswordCheckRequest;
import com.trustshield.breach.dto.PasswordCheckResponse;
import com.trustshield.breach.entity.BreachCheckRecord;
import com.trustshield.breach.hibp.BreachLookupResult;
import com.trustshield.breach.hibp.PwnedPasswordsClient;
import com.trustshield.breach.offline.CommonPasswordCatalog;
import com.trustshield.breach.repository.BreachCheckRecordRepository;
import com.trustshield.breach.strength.PasswordStrengthAnalyzer;
import com.trustshield.breach.strength.StrengthAssessment;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatSignal;
import com.trustshield.common.util.HashUtils;

/**
 * Evaluates password exposure risk by combining external and offline breach corpus
 * membership verification with local structural complexity analysis.
 *
 * <p>Architecture and scoring principles:
 * <ul>
 *   <li><strong>Corpus verification takes precedence:</strong> Verified breach occurrence
 *       directly indicates compromise, flooring the risk score at {@link #EXPOSED_FLOOR}.</li>
 *   <li><strong>Structural complexity:</strong> Local heuristic analysis assesses entropy and
 *       patterns, contributing up to a capped threshold (60 points) when no breach is observed.</li>
 *   <li><strong>Monotonic escalation:</strong> External lookups operate under raise-only semantics;
 *       corpus misses indicate lack of observed exposure in indexed datasets rather than proof of safety.</li>
 * </ul>
 */
@Service
public class PasswordExposureService {

    private static final Logger log = LoggerFactory.getLogger(PasswordExposureService.class);

    /**
     * Minimum score once any source confirms exposure. Chosen to land firmly in
     * {@code DANGEROUS} (>= 75) rather than merely {@code SUSPICIOUS}, because a
     * password in a public wordlist should never be presented as a soft warning.
     */
    static final int EXPOSED_FLOOR = 90;

    private final PwnedPasswordsClient rangeApi;
    private final CommonPasswordCatalog offlineCatalog;
    private final PasswordStrengthAnalyzer strengthAnalyzer;
    private final BreachCheckRecordRepository repository;
    private final long budgetMs;

    public PasswordExposureService(PwnedPasswordsClient rangeApi,
                                   CommonPasswordCatalog offlineCatalog,
                                   PasswordStrengthAnalyzer strengthAnalyzer,
                                   BreachCheckRecordRepository repository,
                                   BreachProperties properties) {
        this.rangeApi = rangeApi;
        this.offlineCatalog = offlineCatalog;
        this.strengthAnalyzer = strengthAnalyzer;
        this.repository = repository;
        this.budgetMs = properties.lookupTimeoutMs();
    }

    @Transactional
    public PasswordCheckResponse check(PasswordCheckRequest request) {
        long started = System.nanoTime();
        String password = request.password();

        // The bucket prefix is the only part of the hash that is ever disclosed
        // or recorded. Computed once, here, so there is a single place to audit.
        String bucketPrefix = HashUtils.sha1HexUpper(password).substring(0, 5);

        StrengthAssessment strength = strengthAnalyzer.analyze(password);
        List<BreachLookupResult> results = consultSources(password);

        List<ThreatSignal> signals = new ArrayList<>();
        List<PasswordCheckResponse.SourceOutcome> outcomes = new ArrayList<>();

        boolean exposed = false;
        boolean anyUnavailable = false;
        // A source "answered" when it reported EXPOSED or NOT_FOUND. Counting these
        // separately from anyUnavailable is what distinguishes a partial picture
        // from no picture at all.
        int sourcesAnswered = 0;
        long highestCount = 0L;

        for (BreachLookupResult r : results) {
            outcomes.add(new PasswordCheckResponse.SourceOutcome(
                    r.source(),
                    r.status().name(),
                    r.occurrences().orElse(null),
                    r.detail()));

            switch (r.status()) {
                case EXPOSED -> {
                    exposed = true;
                    sourcesAnswered++;
                    highestCount = Math.max(highestCount, r.occurrences().orElse(0L));
                    signals.add(ThreatSignal.triggered(
                            "PASSWORD_IN_BREACH_CORPUS",
                            r.occurrences()
                                    .map(c -> "This password appears " + formatCount(c)
                                            + " times in known breach data.")
                                    .orElse("This password is on a published list of "
                                            + "commonly used passwords."),
                            EXPOSED_FLOOR,
                            r.source()));
                }
                case NOT_FOUND -> {
                    sourcesAnswered++;
                    signals.add(ThreatSignal.passed(
                            "NOT_IN_BREACH_CORPUS",
                            "Not found in this breach corpus. That is reassuring but not proof: "
                                    + "no corpus contains every breach.",
                            r.source()));
                }
                case UNAVAILABLE -> {
                    anyUnavailable = true;
                    signals.add(ThreatSignal.passed(
                            "SOURCE_UNAVAILABLE",
                            "This source could not be consulted: " + r.detail(),
                            r.source()));
                }
            }
        }

        // Structural weaknesses contribute, but only up to a ceiling, so that
        // structure alone never reaches DANGEROUS. Reaching DANGEROUS requires
        // observed exposure.
        int structuralContribution = Math.min(60, strength.weaknessScore());
        for (StrengthAssessment.Weakness w : strength.weaknesses()) {
            if (w.penalty() > 0) {
                signals.add(ThreatSignal.triggered(
                        w.code(), w.description(), w.penalty(), "STRUCTURAL_ANALYSIS"));
            } else {
                signals.add(ThreatSignal.passed(
                        w.code(), w.description(), "STRUCTURAL_ANALYSIS"));
            }
        }

        int score = structuralContribution;
        if (exposed) {
            // Raise-only: floor, never average. A hit cannot be diluted by a
            // structurally strong-looking password.
            score = Math.max(score, EXPOSED_FLOOR);
            if (highestCount >= 100_000L) {
                score = Math.max(score, 98);
            } else if (highestCount >= 1_000L) {
                score = Math.max(score, 95);
            }
        }

        boolean noSourceAnswered = sourcesAnswered == 0;

        // INCONCLUSIVE is reserved for the case where *no* source answered, because
        // that is the only case in which the guidance attached to it ("no breach
        // source could be reached") is true. A partial picture -- one source
        // answered NOT_FOUND while another was down -- is NO_EXPOSURE_FOUND with
        // degraded=true, which is a weaker but accurate claim.
        String verdictCode = exposed
                ? "PASSWORD_EXPOSED"
                : noSourceAnswered ? "INCONCLUSIVE" : "NO_EXPOSURE_FOUND";

        String explanation = buildExplanation(
                exposed, anyUnavailable, noSourceAnswered, highestCount, strength);
        long latencyMs = (System.nanoTime() - started) / 1_000_000L;

        // Four outcomes, because "unavailable" is not one situation.
        //
        // The distinction that matters is whether *any* evidence was gathered, from
        // any source -- and structural analysis is a source. It runs locally, so it
        // cannot be unavailable. A password with observed structural weaknesses has
        // a score that means something even when every corpus is down, so pinning
        // it to UNKNOWN would throw away a real finding and under-warn the user.
        // UNKNOWN is reserved for the case where nothing at all was learned.
        //
        // Note the asymmetry: structure having found nothing is *not* evidence of
        // safety, because the analyzer only recognises the weaknesses it knows to
        // look for. So zero structural findings plus zero corpus answers is
        // genuine ignorance, not a weak clean result.
        ModuleVerdict verdict;
        if (exposed) {
            verdict = ModuleVerdict.of(
                    ModuleType.BREACH, score, verdictCode, explanation, signals, latencyMs);
        } else if (noSourceAnswered && structuralContribution == 0) {
            verdict = ModuleVerdict.inconclusive(
                    ModuleType.BREACH, verdictCode, explanation, signals, latencyMs);
        } else if (anyUnavailable) {
            verdict = ModuleVerdict.degraded(
                    ModuleType.BREACH, score, verdictCode, explanation, signals, latencyMs);
        } else {
            verdict = ModuleVerdict.of(
                    ModuleType.BREACH, score, verdictCode, explanation, signals, latencyMs);
        }

        persist(bucketPrefix, verdict, exposed, outcomes, request.context());

        return new PasswordCheckResponse(
                verdict,
                // Deliberately not verdict.threatLevel().getRecommendation() — see
                // Recommendations for why a score of 0 must not be narrated as "safe".
                Recommendations.forPasswordCheck(
                        verdictCode, verdict.threatLevel(), strength.weaknessScore() > 0),
                strength,
                outcomes,
                true,   // neither the password nor its full hash left this process
                bucketPrefix);
    }

    /**
     * Consults every source, in parallel, inside one latency budget.
     *
     * <p>Virtual threads make one-thread-per-lookup free, and
     * {@code invokeAll(tasks, timeout, unit)} bounds the whole batch rather than
     * each task, so total wall-clock stays inside the budget however many sources
     * are added later. A task that overruns is cancelled and reported as
     * unavailable — never as clean.
     */
    private List<BreachLookupResult> consultSources(String password) {
        List<Callable<BreachLookupResult>> tasks = List.of(
                () -> offlineCatalog.check(password),
                () -> rangeApi.check(password));

        List<BreachLookupResult> results = new ArrayList<>();
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<BreachLookupResult>> futures =
                    executor.invokeAll(tasks, budgetMs, TimeUnit.MILLISECONDS);
            for (Future<BreachLookupResult> future : futures) {
                if (future.isCancelled()) {
                    results.add(BreachLookupResult.unavailable(
                            "UNKNOWN_SOURCE", "Exceeded the " + budgetMs + " ms budget"));
                    continue;
                }
                try {
                    results.add(future.get());
                } catch (Exception e) {
                    results.add(BreachLookupResult.unavailable(
                            "UNKNOWN_SOURCE", "Failed: " + e.getClass().getSimpleName()));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            results.add(BreachLookupResult.unavailable("ALL_SOURCES", "Interrupted"));
        }
        return results;
    }

    private void persist(String bucketPrefix,
                         ModuleVerdict verdict,
                         boolean exposed,
                         List<PasswordCheckResponse.SourceOutcome> outcomes,
                         String context) {
        try {
            String summary = outcomes.stream()
                    .map(o -> o.source() + "=" + o.status())
                    .reduce((a, b) -> a + "; " + b)
                    .orElse("none");

            repository.save(BreachCheckRecord.forPassword(bucketPrefix)
                    .withOutcome(verdict.riskScore(), verdict.threatLevel(), verdict.verdict(),
                            exposed, verdict.degraded(), summary, context));
        } catch (Exception e) {
            // An audit-write failure must not deny the user their answer.
            log.warn("Could not persist breach check audit record: {}", e.getMessage());
        }
    }

    private static String buildExplanation(boolean exposed,
                                           boolean anyUnavailable,
                                           boolean noSourceAnswered,
                                           long count,
                                           StrengthAssessment strength) {
        if (exposed) {
            String base = count > 0
                    ? "This password appears " + formatCount(count) + " times in known breach data."
                    : "This password appears on a published list of commonly used passwords.";
            return base + " Treat it as already compromised and change it anywhere it is used. "
                    + "Structural strength is irrelevant once a password has leaked verbatim.";
        }
        if (anyUnavailable) {
            // Distinguish "nothing was checked" from "something was checked and
            // came back clean, but not everything". The first cannot say "no
            // exposure was confirmed" as though that were a partial reassurance.
            String lead = noSourceAnswered
                    ? "No breach source could be consulted, so nothing is known about exposure "
                            + "either way. This is not a clean result."
                    : "No exposure was confirmed, but at least one breach source could not be "
                            + "consulted, so this is inconclusive rather than clean.";
            return lead + " " + describeStructure(strength);
        }
        return "Not found in the breach corpora consulted. This is not proof of safety: "
                + "no corpus contains every breach. " + describeStructure(strength);
    }

    /**
     * Summarizes local structural findings from password entropy and pattern assessment.
     *
     * <p>Filters out non-penalized baseline markers.
     */
    private static String describeStructure(StrengthAssessment strength) {
        long flagged = strength.weaknesses().stream()
                .filter(w -> w.penalty() > 0)
                .count();
        if (flagged == 0) {
            return "Separately, no structural weakness was detected in the password itself.";
        }
        return flagged == 1
                ? "Separately, 1 structural weakness was detected in the password itself."
                : "Separately, " + flagged + " structural weaknesses were detected in the "
                        + "password itself.";
    }

    private static String formatCount(long count) {
        return String.format("%,d", count);
    }
}
