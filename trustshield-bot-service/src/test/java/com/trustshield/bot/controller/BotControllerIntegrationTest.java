package com.trustshield.bot.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.bot.dto.BotMessageRequest;
import com.trustshield.common.dto.IncidentId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class BotControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("POST /api/v1/bot/message processes slash commands")
    void testProcessCommand() throws Exception {
        BotMessageRequest request = new BotMessageRequest(
                IncidentId.generate(),
                "WHATSAPP",
                "+1234567890",
                "/help",
                "NONE",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/bot/message")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.threatLevel").value("SAFE"))
                .andExpect(jsonPath("$.primaryCategory").value("SYSTEM_COMMAND"))
                .andExpect(jsonPath("$.replyText").value(containsString("TrustShield")));
    }

    @Test
    @DisplayName("POST /api/v1/bot/message processes URL scan query")
    void testProcessUrlScan() throws Exception {
        BotMessageRequest request = new BotMessageRequest(
                IncidentId.generate(),
                "TELEGRAM",
                "tg_user_42",
                "Is this safe: https://secure-bank-login.xyz/verify",
                "NONE",
                null,
                null
        );

        mockMvc.perform(post("/api/v1/bot/message")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.channel").value("TELEGRAM"))
                .andExpect(jsonPath("$.primaryCategory").value("PHISHING_URL"))
                .andExpect(jsonPath("$.replyText").value(containsString("TrustShield")));
    }

    @Test
    @DisplayName("GET /webhook/whatsapp verifies valid token and returns challenge")
    void testWhatsAppWebhookHandshakeSuccess() throws Exception {
        mockMvc.perform(get("/webhook/whatsapp")
                        .param("hub.mode", "subscribe")
                        .param("hub.verify_token", "trustshield_webhook_token_2026")
                        .param("hub.challenge", "challenge_12345678"))
                .andExpect(status().isOk())
                .andExpect(content().string("challenge_12345678"));
    }

    @Test
    @DisplayName("GET /webhook/whatsapp rejects invalid verify token")
    void testWhatsAppWebhookHandshakeForbidden() throws Exception {
        mockMvc.perform(get("/webhook/whatsapp")
                        .param("hub.mode", "subscribe")
                        .param("hub.verify_token", "unauthorized_token")
                        .param("hub.challenge", "challenge_12345678"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /webhook/whatsapp ingests standard Meta webhook payload")
    void testWhatsAppWebhookMessage() throws Exception {
        Map<String, Object> payload = Map.of(
                "object", "whatsapp_business_account",
                "entry", List.of(
                        Map.of("changes", List.of(
                                Map.of("value", Map.of(
                                        "messaging_product", "whatsapp",
                                        "messages", List.of(
                                                Map.of(
                                                        "from", "16505551234",
                                                        "type", "text",
                                                        "text", Map.of("body", "/rules")
                                                )
                                        )
                                ))
                        ))
                )
        );

        mockMvc.perform(post("/webhook/whatsapp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.replyText").value(containsString("TrustShield Auditable Fusion Rules")));
    }

    @Test
    @DisplayName("POST /webhook/telegram ingests Telegram bot update payload")
    void testTelegramWebhookMessage() throws Exception {
        Map<String, Object> payload = Map.of(
                "update_id", 12345,
                "message", Map.of(
                        "message_id", 99,
                        "from", Map.of("id", 888123, "username", "alice"),
                        "text", "password: WeakPassword123"
                )
        );

        mockMvc.perform(post("/webhook/telegram")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.primaryCategory").value("PASSWORD_BREACH"));
    }

    @Test
    @DisplayName("GET /api/v1/bot/history returns audit records")
    void testGetHistory() throws Exception {
        mockMvc.perform(get("/api/v1/bot/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("GET /api/v1/bot/stats returns aggregate metrics")
    void testGetStats() throws Exception {
        mockMvc.perform(get("/api/v1/bot/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalInteractions").exists());
    }

    @Test
    @DisplayName("GET /api/v1/bot/info returns service metadata")
    void testGetInfo() throws Exception {
        mockMvc.perform(get("/api/v1/bot/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("trustshield-bot-service"))
                .andExpect(jsonPath("$.port").value(8089));
    }
}
