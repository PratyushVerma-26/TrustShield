package com.trustshield.bot.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ThreatLevel;

import java.util.List;

/**
 * Outgoing conversational threat intelligence response formatted for messaging apps.
 *
 * @param incidentId correlation identifier
 * @param channel recipient platform ("WHATSAPP", "TELEGRAM", "WEB_CHAT")
 * @param recipientId destination user identifier
 * @param replyText formatted markdown reply with visual badges and guidance
 * @param threatLevel composite threat rating
 * @param riskScore numeric risk indicator (0-100)
 * @param primaryCategory classification of analyzed threat
 * @param recommendations actionable safety advice
 * @param latencyMs processing latency
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BotMessageResponse(
        IncidentId incidentId,
        String channel,
        String recipientId,
        String replyText,
        ThreatLevel threatLevel,
        int riskScore,
        String primaryCategory,
        List<String> recommendations,
        long latencyMs
) {
    public BotMessageResponse {
        recommendations = recommendations != null ? List.copyOf(recommendations) : List.of();
    }
}
