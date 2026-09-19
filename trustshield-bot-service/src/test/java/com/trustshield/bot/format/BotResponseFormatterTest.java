package com.trustshield.bot.format;

import com.trustshield.bot.dto.BotMessageResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BotResponseFormatterTest {

    private BotResponseFormatter formatter;

    @BeforeEach
    void setUp() {
        formatter = new BotResponseFormatter();
    }

    @Test
    @DisplayName("Formats DANGEROUS phishing verdict with warning badge and urgent action guidance")
    void testFormatDangerousVerdict() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.PHISHING,
                92,
                "PHISHING_DETECTED",
                "Domain mimics State Bank of India with brand impersonation heuristic.",
                List.of(),
                12L
        );

        BotMessageResponse response = formatter.formatVerdict(
                id,
                "WHATSAPP",
                "+123456789",
                "PHISHING_URL",
                verdict,
                15L
        );

        assertEquals(ThreatLevel.DANGEROUS, response.threatLevel());
        assertEquals(92, response.riskScore());
        assertTrue(response.replyText().contains("🚨 *DANGEROUS THREAT DETECTED*"));
        assertTrue(response.replyText().contains("*(92/100)*"));
        assertTrue(response.replyText().contains("Do NOT click this link"));
        assertTrue(response.replyText().contains(id.value()));
    }

    @Test
    @DisplayName("Formats UNKNOWN verdict with refusal to certify unverified content as safe")
    void testFormatUnknownVerdict() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = ModuleVerdict.inconclusive(
                ModuleType.DEEPFAKE,
                "IMAGE_RECOMPRESSED",
                "High JPEG compression eliminated fine sensor noise artifacts.",
                List.of(),
                8L
        );

        BotMessageResponse response = formatter.formatVerdict(
                id,
                "TELEGRAM",
                "tg_user",
                "SYNTHETIC_MEDIA",
                verdict,
                10L
        );

        assertEquals(ThreatLevel.UNKNOWN, response.threatLevel());
        assertEquals(0, response.riskScore());
        assertTrue(response.replyText().contains("❓ *INCONCLUSIVE / UNVERIFIED*"));
        assertTrue(response.replyText().contains("refuses to falsely certify unverified content"));
    }

    @Test
    @DisplayName("Formats SAFE verdict with positive confirmation badge")
    void testFormatSafeVerdict() {
        IncidentId id = IncidentId.generate();
        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.PHISHING,
                5,
                "BENIGN",
                "Well known domain with legitimate TLS certificates and reputation history.",
                List.of(),
                15L
        );

        BotMessageResponse response = formatter.formatVerdict(
                id,
                "WEB_CHAT",
                "web_user",
                "PHISHING_URL",
                verdict,
                18L
        );

        assertEquals(ThreatLevel.SAFE, response.threatLevel());
        assertTrue(response.replyText().contains("🛡️ *NO THREATS DETECTED*"));
        assertFalse(response.recommendations().isEmpty());
    }

    @Test
    @DisplayName("Formats /start, /help, and /rules commands correctly")
    void testFormatCommands() {
        IncidentId id = IncidentId.generate();

        BotMessageResponse help = formatter.formatCommandResponse(id, "WHATSAPP", "+123", "/help");
        assertTrue(help.replyText().contains("TrustShield Cyber-Defense Bot"));
        assertTrue(help.replyText().contains("`/rules`"));

        BotMessageResponse rules = formatter.formatCommandResponse(id, "WHATSAPP", "+123", "/rules");
        assertTrue(rules.replyText().contains("TrustShield Auditable Fusion Rules (R1–R5)"));
        assertTrue(rules.replyText().contains("R1 (Dangerous Escalation)"));
    }
}
