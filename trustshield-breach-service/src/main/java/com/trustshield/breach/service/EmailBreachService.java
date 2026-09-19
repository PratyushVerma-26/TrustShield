package com.trustshield.breach.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.trustshield.breach.dto.EmailCheckRequest;
import com.trustshield.breach.dto.EmailCheckResponse;
import com.trustshield.breach.entity.BreachCheckRecord;
import com.trustshield.breach.hibp.BreachLookupResult;
import com.trustshield.breach.hibp.HibpAccountClient;
import com.trustshield.breach.repository.BreachCheckRecordRepository;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatSignal;
import com.trustshield.common.util.HashUtils;

/**
 * Service managing email breach lookups with explicit user consent and privacy controls.
 *
 * <p>Operational safeguards:
 * <ol>
 *   <li>Requires {@link EmailCheckRequest#acknowledged()} to be {@code true} before dispatching external queries.</li>
 *   <li>Reports {@code kAnonymous=false} across all responses to indicate direct external API interaction.</li>
 *   <li>Persists only pseudonymized SHA-256 hashes of queried email addresses for audit logging.</li>
 * </ol>
 *
 * <p>Scoring reflects the volume and sensitivity of confirmed breaches reported by external sources.
 * If sources are unreachable, the verdict degrades with an inconclusive status.
 */
@Service
public class EmailBreachService {

    private static final Logger log = LoggerFactory.getLogger(EmailBreachService.class);

    private static final String NOTICE_TRANSMITTED =
            "Your full email address was sent to the Have I Been Pwned API to perform this lookup. "
                    + "Unlike the password check, no k-anonymity is possible for this operation: "
                    + "the breached-account endpoint has no prefix-based variant.";

    private static final String NOTICE_NOT_TRANSMITTED =
            "Nothing was transmitted. This lookup did not run.";

    private final HibpAccountClient client;
    private final BreachCheckRecordRepository repository;

    public EmailBreachService(HibpAccountClient client, BreachCheckRecordRepository repository) {
        this.client = client;
        this.repository = repository;
    }

    @Transactional
    public EmailCheckResponse check(EmailCheckRequest request) {
        long started = System.nanoTime();
        String normalised = request.email().trim().toLowerCase(Locale.ROOT);
        String subjectHash = HashUtils.sha256Hex(normalised);

        if (!request.acknowledged()) {
            ModuleVerdict refused = ModuleVerdict.notApplicable(ModuleType.BREACH,
                    "This lookup transmits your full email address to a third party, so it requires "
                            + "explicit acknowledgement. Resend with \"acknowledged\": true.");
            return new EmailCheckResponse(refused,
                    Recommendations.forEmailCheck(refused.verdict(), 0),
                    List.of(), false, NOTICE_NOT_TRANSMITTED);
        }

        if (!client.isUsable()) {
            // inconclusive, not degraded: no lookup was attempted at all, so a
            // score of 0 records ignorance rather than a clean result.
            ModuleVerdict unavailable = ModuleVerdict.inconclusive(ModuleType.BREACH,
                    "SOURCE_UNAVAILABLE",
                    "Email breach lookup is not configured. It needs a Have I Been Pwned API key, "
                            + "which is a paid subscription, so it is disabled by default. "
                            + "The password check needs no key and works offline.",
                    List.of(ThreatSignal.passed("HIBP_NOT_CONFIGURED",
                            "No API key present, so no lookup was attempted.",
                            HibpAccountClient.SOURCE)),
                    (System.nanoTime() - started) / 1_000_000L);
            return new EmailCheckResponse(unavailable,
                    Recommendations.forEmailCheck(unavailable.verdict(), 0),
                    List.of(), false, NOTICE_NOT_TRANSMITTED);
        }

        HibpAccountClient.AccountLookup lookup = client.lookup(normalised);
        BreachLookupResult result = lookup.result();

        List<ThreatSignal> signals = new ArrayList<>();
        List<EmailCheckResponse.BreachSummary> summaries = new ArrayList<>();
        int score = 0;
        boolean sensitiveSeen = false;

        switch (result.status()) {
            case EXPOSED -> {
                for (HibpAccountClient.HibpBreach b : lookup.breaches()) {
                    summaries.add(new EmailCheckResponse.BreachSummary(
                            b.name(), b.title(), b.domain(), b.breachDate(),
                            b.pwnCount(), b.dataClasses(), b.verified()));
                    if (Boolean.TRUE.equals(b.sensitive())) {
                        sensitiveSeen = true;
                    }
                }
                // 20 points per breach, capped, plus a bump for sensitive breaches.
                score = Math.min(85, 20 * summaries.size());
                if (sensitiveSeen) {
                    score = Math.min(95, score + 10);
                }
                signals.add(ThreatSignal.triggered("EMAIL_IN_BREACHES",
                        "This address appears in " + summaries.size()
                                + " breach(es) known to the source.",
                        score, HibpAccountClient.SOURCE));
                if (sensitiveSeen) {
                    signals.add(ThreatSignal.triggered("SENSITIVE_BREACH",
                            "At least one breach is flagged sensitive by the source, meaning "
                                    + "disclosure could itself cause harm.",
                            10, HibpAccountClient.SOURCE));
                }
            }
            case NOT_FOUND -> signals.add(ThreatSignal.passed("EMAIL_NOT_IN_BREACHES",
                    "This address was not found in the source's breach set. Breaches that are "
                            + "unreported or not yet public would not appear.",
                    HibpAccountClient.SOURCE));
            case UNAVAILABLE -> signals.add(ThreatSignal.passed("SOURCE_UNAVAILABLE",
                    "The lookup could not be completed: " + result.detail(),
                    HibpAccountClient.SOURCE));
        }

        long latencyMs = (System.nanoTime() - started) / 1_000_000L;
        String verdictCode = switch (result.status()) {
            case EXPOSED -> "EMAIL_EXPOSED";
            case NOT_FOUND -> "NO_EXPOSURE_FOUND";
            case UNAVAILABLE -> "INCONCLUSIVE";
        };

        // There is exactly one source here, so "unavailable" means nothing was
        // learned -- unlike the password path, where one source can answer while
        // another is down. Hence inconclusive rather than degraded.
        ModuleVerdict verdict = result.isUnavailable()
                ? ModuleVerdict.inconclusive(ModuleType.BREACH, verdictCode,
                        explain(result, summaries.size()), signals, latencyMs)
                : ModuleVerdict.of(ModuleType.BREACH, score, verdictCode,
                        explain(result, summaries.size()), signals, latencyMs);

        persist(subjectHash, verdict, result.isExposed());

        return new EmailCheckResponse(verdict,
                Recommendations.forEmailCheck(verdictCode, summaries.size()),
                summaries, false, NOTICE_TRANSMITTED);
    }

    private void persist(String subjectHash, ModuleVerdict verdict, boolean exposed) {
        try {
            repository.save(BreachCheckRecord.forEmail(subjectHash)
                    .withOutcome(verdict.riskScore(), verdict.threatLevel(), verdict.verdict(),
                            exposed, verdict.degraded(),
                            HibpAccountClient.SOURCE + "=" + verdict.verdict(), null));
        } catch (Exception e) {
            log.warn("Could not persist email breach audit record: {}", e.getMessage());
        }
    }

    private static String explain(BreachLookupResult result, int breachCount) {
        return switch (result.status()) {
            case EXPOSED -> "This address appears in " + breachCount + " known breach(es). "
                    + "Change the password on the affected services, and anywhere you reused it. "
                    + "Enable two-factor authentication where it is offered.";
            case NOT_FOUND -> "This address was not found in the breaches known to the source. "
                    + "That is not proof of safety: breaches that are undisclosed or not yet "
                    + "public cannot appear in any corpus.";
            case UNAVAILABLE -> "The breach lookup could not be completed, so this result is "
                    + "inconclusive rather than clean. " + result.detail();
        };
    }
}
