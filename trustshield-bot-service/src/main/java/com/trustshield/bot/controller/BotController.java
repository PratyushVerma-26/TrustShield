package com.trustshield.bot.controller;

import com.trustshield.bot.dto.BotMessageRequest;
import com.trustshield.bot.dto.BotMessageResponse;
import com.trustshield.bot.entity.BotInteractionRecord;
import com.trustshield.bot.router.MicroserviceRouter;
import com.trustshield.bot.service.BotService;
import com.trustshield.common.dto.IncidentId;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller exposing multi-channel bot conversational interfaces and webhooks.
 */
@RestController
@RequestMapping
@Tag(name = "Conversational Cyber-Defense Bot", description = "WhatsApp, Telegram, and Web Chat integration endpoints")
public class BotController {

    private static final Logger log = LoggerFactory.getLogger(BotController.class);

    private final BotService botService;
    private final MicroserviceRouter microserviceRouter;
    private final String whatsappVerifyToken;

    public BotController(
            BotService botService,
            MicroserviceRouter microserviceRouter,
            @Value("${trustshield.bot.whatsapp-verify-token:trustshield_webhook_token_2026}") String whatsappVerifyToken) {
        this.botService = botService;
        this.microserviceRouter = microserviceRouter;
        this.whatsappVerifyToken = whatsappVerifyToken;
    }

    @PostMapping(
            value = {"/api/v1/bot/message", "/api/v1/bot/analyze"},
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(summary = "Process conversational security query", description = "Classifies intent, dispatches to forensic detectors, formats markdown threat badge, and records in audit ledger.")
    public ResponseEntity<BotMessageResponse> processMessage(@Valid @RequestBody BotMessageRequest request) {
        BotMessageResponse response = botService.processMessage(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/webhook/whatsapp")
    @Operation(summary = "WhatsApp Cloud API verification handshake", description = "Echoes hub.challenge if hub.verify_token matches configured secret.")
    public ResponseEntity<String> verifyWhatsAppWebhook(
            @RequestParam(value = "hub.mode", required = false) String mode,
            @RequestParam(value = "hub.verify_token", required = false) String verifyToken,
            @RequestParam(value = "hub.challenge", required = false) String challenge) {

        if ("subscribe".equalsIgnoreCase(mode) && whatsappVerifyToken.equals(verifyToken)) {
            return ResponseEntity.ok(challenge != null ? challenge : "");
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Verification token mismatch");
    }

    @PostMapping(value = "/webhook/whatsapp", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "WhatsApp Cloud API webhook receiver", description = "Receives forwarded WhatsApp messages, performs threat scan, and returns formatted reply.")
    public ResponseEntity<BotMessageResponse> receiveWhatsAppWebhook(@RequestBody Map<String, Object> payload) {
        BotMessageRequest request = parseWhatsAppPayload(payload);
        BotMessageResponse response = botService.processMessage(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "/webhook/telegram", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Telegram Bot API webhook receiver", description = "Receives Telegram updates, performs threat scan, and returns formatted reply.")
    public ResponseEntity<BotMessageResponse> receiveTelegramWebhook(@RequestBody Map<String, Object> payload) {
        BotMessageRequest request = parseTelegramPayload(payload);
        BotMessageResponse response = botService.processMessage(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = "/api/v1/bot/history", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Recent bot interaction history", description = "Returns 25 most recent conversational scans.")
    public ResponseEntity<List<BotInteractionRecord>> getHistory() {
        return ResponseEntity.ok(botService.getRecentHistory());
    }

    @GetMapping(value = "/api/v1/bot/stats", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Bot interaction statistics", description = "Aggregate interaction counts by threat level and platform.")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(botService.getStats());
    }

    @GetMapping(value = "/api/v1/bot/info", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "Bot service operational metadata")
    public ResponseEntity<Map<String, Object>> getInfo() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("service", "trustshield-bot-service");
        info.put("port", 8089);
        info.put("status", "UP");
        info.put("channels", List.of("WHATSAPP", "TELEGRAM", "WEB_CHAT"));
        info.put("version", "1.0.0");
        info.put("services", Map.of(
                "phishing", microserviceRouter.getPhishingUrl(),
                "breach", microserviceRouter.getBreachUrl(),
                "deepfake", microserviceRouter.getDeepfakeUrl(),
                "fakenews", microserviceRouter.getFakenewsUrl(),
                "fusion", microserviceRouter.getFusionUrl(),
                "integrity", microserviceRouter.getIntegrityUrl()
        ));
        return ResponseEntity.ok(info);
    }

    @SuppressWarnings("unchecked")
    private BotMessageRequest parseWhatsAppPayload(Map<String, Object> payload) {
        String senderId = "whatsapp_user";
        String messageText = "";
        String mediaType = "NONE";
        String mediaBase64 = null;

        try {
            if (payload.containsKey("entry")) {
                List<Map<String, Object>> entryList = (List<Map<String, Object>>) payload.get("entry");
                if (entryList != null && !entryList.isEmpty()) {
                    List<Map<String, Object>> changes = (List<Map<String, Object>>) entryList.getFirst().get("changes");
                    if (changes != null && !changes.isEmpty()) {
                        Map<String, Object> value = (Map<String, Object>) changes.getFirst().get("value");
                        if (value != null && value.containsKey("messages")) {
                            List<Map<String, Object>> messages = (List<Map<String, Object>>) value.get("messages");
                            if (messages != null && !messages.isEmpty()) {
                                Map<String, Object> msg = messages.getFirst();
                                senderId = String.valueOf(msg.getOrDefault("from", "whatsapp_user"));
                                String type = String.valueOf(msg.getOrDefault("type", "text"));
                                if ("text".equalsIgnoreCase(type)) {
                                    Map<String, Object> textObj = (Map<String, Object>) msg.get("text");
                                    if (textObj != null) {
                                        messageText = String.valueOf(textObj.getOrDefault("body", ""));
                                    }
                                } else if ("image".equalsIgnoreCase(type)) {
                                    mediaType = "IMAGE";
                                    Map<String, Object> img = (Map<String, Object>) msg.get("image");
                                    if (img != null && img.containsKey("caption")) {
                                        messageText = String.valueOf(img.get("caption"));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if (payload.containsKey("from")) senderId = String.valueOf(payload.get("from"));
                else if (payload.containsKey("senderId")) senderId = String.valueOf(payload.get("senderId"));

                if (payload.containsKey("text")) messageText = String.valueOf(payload.get("text"));
                else if (payload.containsKey("messageText")) messageText = String.valueOf(payload.get("messageText"));

                if (payload.containsKey("mediaType")) mediaType = String.valueOf(payload.get("mediaType"));
                if (payload.containsKey("mediaBase64")) mediaBase64 = String.valueOf(payload.get("mediaBase64"));
            }
        } catch (Exception e) {
            log.warn("Error parsing WhatsApp webhook payload: {}", e.getMessage());
        }

        return new BotMessageRequest(IncidentId.generate(), "WHATSAPP", senderId, messageText, mediaType, mediaBase64, null);
    }

    @SuppressWarnings("unchecked")
    private BotMessageRequest parseTelegramPayload(Map<String, Object> payload) {
        String senderId = "telegram_user";
        String messageText = "";
        String mediaType = "NONE";
        String mediaBase64 = null;

        try {
            if (payload.containsKey("message")) {
                Map<String, Object> message = (Map<String, Object>) payload.get("message");
                if (message != null) {
                    if (message.containsKey("from")) {
                        Map<String, Object> from = (Map<String, Object>) message.get("from");
                        if (from != null && from.containsKey("id")) {
                            senderId = String.valueOf(from.get("id"));
                        }
                    } else if (message.containsKey("chat")) {
                        Map<String, Object> chat = (Map<String, Object>) message.get("chat");
                        if (chat != null && chat.containsKey("id")) {
                            senderId = String.valueOf(chat.get("id"));
                        }
                    }
                    if (message.containsKey("text")) {
                        messageText = String.valueOf(message.get("text"));
                    } else if (message.containsKey("caption")) {
                        messageText = String.valueOf(message.get("caption"));
                    }
                    if (message.containsKey("photo")) {
                        mediaType = "IMAGE";
                    } else if (message.containsKey("video")) {
                        mediaType = "VIDEO";
                    } else if (message.containsKey("voice") || message.containsKey("audio")) {
                        mediaType = "AUDIO";
                    }
                }
            } else {
                if (payload.containsKey("senderId")) senderId = String.valueOf(payload.get("senderId"));
                else if (payload.containsKey("chat_id")) senderId = String.valueOf(payload.get("chat_id"));

                if (payload.containsKey("text")) messageText = String.valueOf(payload.get("text"));
                else if (payload.containsKey("messageText")) messageText = String.valueOf(payload.get("messageText"));

                if (payload.containsKey("mediaType")) mediaType = String.valueOf(payload.get("mediaType"));
                if (payload.containsKey("mediaBase64")) mediaBase64 = String.valueOf(payload.get("mediaBase64"));
            }
        } catch (Exception e) {
            log.warn("Error parsing Telegram webhook payload: {}", e.getMessage());
        }

        return new BotMessageRequest(IncidentId.generate(), "TELEGRAM", senderId, messageText, mediaType, mediaBase64, null);
    }
}
