package com.trustshield.bot.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.trustshield.common.dto.IncidentId;

/**
 * Incoming conversational message request from WhatsApp, Telegram, or Web Chat.
 *
 * @param incidentId optional correlation ID
 * @param channel origin platform ("WHATSAPP", "TELEGRAM", "WEB_CHAT")
 * @param senderId user phone number or chat identifier
 * @param messageText raw conversational message or caption
 * @param mediaType category of attached file ("IMAGE", "VIDEO", "AUDIO", "NONE")
 * @param mediaBase64 base64 encoded media payload
 * @param mediaFilename optional filename
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BotMessageRequest(
        IncidentId incidentId,
        String channel,
        String senderId,
        String messageText,
        String mediaType,
        String mediaBase64,
        String mediaFilename
) {
    public BotMessageRequest(String channel, String senderId, String messageText) {
        this(IncidentId.generate(), channel, senderId, messageText, "NONE", null, null);
    }

    public BotMessageRequest {
        incidentId = incidentId != null ? incidentId : IncidentId.generate();
        channel = channel != null ? channel.toUpperCase() : "WEB_CHAT";
        senderId = senderId != null ? senderId : "anonymous_user";
        messageText = messageText != null ? messageText.trim() : "";
        mediaType = mediaType != null ? mediaType.toUpperCase() : (mediaBase64 != null ? "IMAGE" : "NONE");
    }
}
