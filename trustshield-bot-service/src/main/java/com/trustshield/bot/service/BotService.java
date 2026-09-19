package com.trustshield.bot.service;

import com.trustshield.bot.dto.BotMessageRequest;
import com.trustshield.bot.dto.BotMessageResponse;
import com.trustshield.bot.entity.BotInteractionRecord;
import com.trustshield.bot.format.BotResponseFormatter;
import com.trustshield.bot.intent.MessageIntentClassifier;
import com.trustshield.bot.repository.BotInteractionRecordRepository;
import com.trustshield.bot.router.MicroserviceRouter;
import com.trustshield.common.dto.IncidentFusionResponse;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Orchestrates multi-channel conversational cyber-defense workflows.
 */
@Service
public class BotService {

    private static final Logger log = LoggerFactory.getLogger(BotService.class);

    private final MessageIntentClassifier intentClassifier;
    private final MicroserviceRouter microserviceRouter;
    private final BotResponseFormatter responseFormatter;
    private final BotInteractionRecordRepository repository;

    public BotService(
            MessageIntentClassifier intentClassifier,
            MicroserviceRouter microserviceRouter,
            BotResponseFormatter responseFormatter,
            BotInteractionRecordRepository repository) {
        this.intentClassifier = intentClassifier;
        this.microserviceRouter = microserviceRouter;
        this.responseFormatter = responseFormatter;
        this.repository = repository;
    }

    /**
     * Ingests, analyzes, formats, and persists an incoming conversational message.
     */
    public BotMessageResponse processMessage(BotMessageRequest request) {
        long startTime = System.currentTimeMillis();
        MessageIntentClassifier.IntentResult intent = intentClassifier.classify(request);

        BotMessageResponse response;
        String category;

        switch (intent.intentType()) {
            case COMMAND -> {
                category = "SYSTEM_COMMAND";
                response = responseFormatter.formatCommandResponse(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        intent.commandName()
                );
            }

            case PHISHING_URL -> {
                category = "PHISHING_URL";
                List<String> urls = intent.extractedUrls();
                ModuleVerdict verdict;
                if (urls.size() > 1) {
                    List<ModuleVerdict> verdicts = new ArrayList<>();
                    for (String url : urls) {
                        verdicts.add(microserviceRouter.scanUrl(url, request.incidentId()));
                    }
                    IncidentFusionResponse fusion = microserviceRouter.evaluateFusion(verdicts, request.incidentId());
                    verdict = fusion.aggregateVerdict();
                } else if (!urls.isEmpty()) {
                    verdict = microserviceRouter.scanUrl(urls.getFirst(), request.incidentId());
                } else {
                    verdict = microserviceRouter.scanUrl(intent.cleanedQueryText(), request.incidentId());
                }

                long latency = System.currentTimeMillis() - startTime;
                response = responseFormatter.formatVerdict(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        category,
                        verdict,
                        latency
                );
                microserviceRouter.appendAuditLedger(request.incidentId(), ModuleType.PHISHING, verdict.verdict());
            }

            case VIRAL_CLAIM -> {
                category = "VIRAL_HOAX";
                ModuleVerdict verdict = microserviceRouter.checkClaim(
                        intent.cleanedQueryText(),
                        request.mediaBase64(),
                        request.mediaType(),
                        request.incidentId()
                );

                long latency = System.currentTimeMillis() - startTime;
                response = responseFormatter.formatVerdict(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        category,
                        verdict,
                        latency
                );
                microserviceRouter.appendAuditLedger(request.incidentId(), ModuleType.FAKENEWS, verdict.verdict());
            }

            case MULTIMODAL_MEDIA -> {
                ModuleVerdict mediaVerdict = microserviceRouter.scanMedia(
                        request.mediaBase64(),
                        request.mediaType(),
                        request.mediaFilename(),
                        request.incidentId()
                );

                List<String> urls = intent.extractedUrls();
                ModuleVerdict finalVerdict = mediaVerdict;
                category = "SYNTHETIC_MEDIA";

                if (!urls.isEmpty() || (intent.cleanedQueryText() != null && intent.cleanedQueryText().length() >= 25)) {
                    List<ModuleVerdict> verdicts = new ArrayList<>();
                    verdicts.add(mediaVerdict);
                    if (!urls.isEmpty()) {
                        verdicts.add(microserviceRouter.scanUrl(urls.getFirst(), request.incidentId()));
                    }
                    if (intent.cleanedQueryText() != null && intent.cleanedQueryText().length() >= 25) {
                        verdicts.add(microserviceRouter.checkClaim(intent.cleanedQueryText(), null, "TEXT", request.incidentId()));
                    }
                    IncidentFusionResponse fusion = microserviceRouter.evaluateFusion(verdicts, request.incidentId());
                    finalVerdict = fusion.aggregateVerdict();
                    category = "MULTIMODAL_THREAT";
                }

                long latency = System.currentTimeMillis() - startTime;
                response = responseFormatter.formatVerdict(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        category,
                        finalVerdict,
                        latency
                );
                microserviceRouter.appendAuditLedger(request.incidentId(), ModuleType.DEEPFAKE, finalVerdict.verdict());
            }

            case PASSWORD_BREACH -> {
                category = "PASSWORD_BREACH";
                ModuleVerdict verdict = microserviceRouter.checkPassword(intent.cleanedQueryText(), request.incidentId());
                long latency = System.currentTimeMillis() - startTime;
                response = responseFormatter.formatVerdict(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        category,
                        verdict,
                        latency
                );
                microserviceRouter.appendAuditLedger(request.incidentId(), ModuleType.BREACH, verdict.verdict());
            }

            case GENERAL_SAFETY -> {
                category = "GENERAL_SAFETY";
                response = responseFormatter.formatCommandResponse(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        "/help"
                );
            }

            default -> {
                category = "UNKNOWN";
                ModuleVerdict verdict = ModuleVerdict.notApplicable(ModuleType.FUSION, "Unrecognized message intent");
                long latency = System.currentTimeMillis() - startTime;
                response = responseFormatter.formatVerdict(
                        request.incidentId(),
                        request.channel(),
                        request.senderId(),
                        category,
                        verdict,
                        latency
                );
            }
        }

        // Persist interaction record in H2
        try {
            BotInteractionRecord record = new BotInteractionRecord(
                    request.incidentId().value(),
                    request.channel(),
                    request.senderId(),
                    intent.intentType().name(),
                    response.threatLevel(),
                    response.riskScore(),
                    category,
                    truncateText(request.messageText(), 4000),
                    response.latencyMs(),
                    Instant.now()
            );
            repository.save(record);
        } catch (Exception e) {
            log.warn("Failed to persist bot interaction record: {}", e.getMessage());
        }

        return response;
    }

    public List<BotInteractionRecord> getRecentHistory() {
        return repository.findTop25ByOrderByCreatedAtDesc();
    }

    public Map<String, Object> getStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalInteractions", repository.count());
        stats.put("dangerousInteractions", repository.countByThreatLevel(ThreatLevel.DANGEROUS));
        stats.put("suspiciousInteractions", repository.countByThreatLevel(ThreatLevel.SUSPICIOUS));
        stats.put("whatsappCount", repository.countByChannel("WHATSAPP"));
        stats.put("telegramCount", repository.countByChannel("TELEGRAM"));
        stats.put("webChatCount", repository.countByChannel("WEB_CHAT"));
        return stats;
    }

    private String truncateText(String text, int maxLen) {
        if (text == null) return "";
        return text.length() <= maxLen ? text : text.substring(0, maxLen);
    }
}
