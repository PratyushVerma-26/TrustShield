package com.trustshield.breach.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.trustshield.breach.dto.BreachHistoryItem;
import com.trustshield.breach.entity.BreachCheckRecord;
import com.trustshield.breach.hibp.HibpAccountClient;
import com.trustshield.breach.offline.CommonPasswordCatalog;
import com.trustshield.breach.hibp.PwnedPasswordsClient;
import com.trustshield.breach.repository.BreachCheckRecordRepository;

/**
 * Read-only view over the audit trail, kept separate from the two check services
 * so neither of them grows reporting responsibilities.
 *
 * <p>The stats map reports {@code degradedChecks} alongside the totals on
 * purpose. A dashboard that shows only "checks run" and "exposures found" hides
 * the most important operational fact: how often the system could not actually
 * reach a source and answered with reduced confidence. That number should be
 * visible during the demo, not discovered afterwards.
 */
@Service
public class BreachAuditService {

    private static final int HISTORY_LIMIT = 25;

    private final BreachCheckRecordRepository repository;
    private final CommonPasswordCatalog offlineCatalog;
    private final PwnedPasswordsClient rangeApi;
    private final HibpAccountClient accountClient;

    public BreachAuditService(BreachCheckRecordRepository repository,
                              CommonPasswordCatalog offlineCatalog,
                              PwnedPasswordsClient rangeApi,
                              HibpAccountClient accountClient) {
        this.repository = repository;
        this.offlineCatalog = offlineCatalog;
        this.rangeApi = rangeApi;
        this.accountClient = accountClient;
    }

    @Transactional(readOnly = true)
    public List<BreachHistoryItem> recentChecks() {
        return repository.findAllByOrderByCheckedAtDesc(PageRequest.of(0, HISTORY_LIMIT))
                .stream()
                .map(BreachHistoryItem::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> stats() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("totalChecks", repository.count());
        body.put("passwordChecks", repository.countByCheckType(BreachCheckRecord.CheckType.PASSWORD));
        body.put("emailChecks", repository.countByCheckType(BreachCheckRecord.CheckType.EMAIL));
        body.put("exposuresFound", repository.countByExposedTrue());
        body.put("degradedChecks", repository.countByDegradedTrue());

        Map<String, Object> sources = new LinkedHashMap<>();
        sources.put("offlineCatalogEntries", offlineCatalog.size());
        sources.put("pwnedPasswordsRangeApiEnabled", rangeApi.isEnabled());
        sources.put("hibpAccountApiUsable", accountClient.isUsable());
        body.put("sources", sources);

        return body;
    }

    /** What each endpoint does and does not disclose, served as data. */
    public Map<String, Object> privacyCard() {
        Map<String, Object> passwordCard = new LinkedHashMap<>();
        passwordCard.put("kAnonymous", true);
        passwordCard.put("transmitted",
                "The first 5 hex characters of the SHA-1 hash, and only if the range API is enabled.");
        passwordCard.put("bucketSize", "1 of 16^5 = 1,048,576 possible prefixes");
        passwordCard.put("apiKeyRequired", false);
        passwordCard.put("worksOffline", true);
        passwordCard.put("stored", "The 5-character bucket prefix. Never the password or its full hash.");

        Map<String, Object> emailCard = new LinkedHashMap<>();
        emailCard.put("kAnonymous", false);
        emailCard.put("transmitted",
                "The full email address, to the HIBP breached-account endpoint. There is no "
                        + "prefix-based variant of this API, so no k-anonymity is achievable.");
        emailCard.put("apiKeyRequired", true);
        emailCard.put("worksOffline", false);
        emailCard.put("requiresAcknowledgement", true);
        emailCard.put("stored",
                "SHA-256 of the lower-cased address. This is pseudonymisation, not "
                        + "anonymisation: email addresses have low entropy, so a candidate list "
                        + "can confirm a guess.");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("passwordCheck", passwordCard);
        body.put("emailCheck", emailCard);
        body.put("note",
                "These two endpoints have genuinely different privacy properties. The k-anonymity "
                        + "guarantee applies to the Pwned Passwords range protocol only; describing "
                        + "the email lookup as k-anonymous would be false.");
        return body;
    }
}
