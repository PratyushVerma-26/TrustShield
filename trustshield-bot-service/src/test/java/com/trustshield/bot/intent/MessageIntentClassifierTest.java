package com.trustshield.bot.intent;

import com.trustshield.bot.dto.BotMessageRequest;
import com.trustshield.common.dto.IncidentId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MessageIntentClassifierTest {

    private MessageIntentClassifier classifier;

    @BeforeEach
    void setUp() {
        classifier = new MessageIntentClassifier();
    }

    @Test
    @DisplayName("Classifies slash command /start and /help correctly")
    void testCommandClassification() {
        BotMessageRequest req = new BotMessageRequest("WHATSAPP", "+1234567890", "/start");
        MessageIntentClassifier.IntentResult result = classifier.classify(req);

        assertEquals(MessageIntentClassifier.IntentType.COMMAND, result.intentType());
        assertEquals("/start", result.commandName());

        BotMessageRequest helpReq = new BotMessageRequest("TELEGRAM", "tg_user", "/help me please");
        MessageIntentClassifier.IntentResult helpRes = classifier.classify(helpReq);
        assertEquals(MessageIntentClassifier.IntentType.COMMAND, helpRes.intentType());
        assertEquals("/help", helpRes.commandName());
        assertEquals("me please", helpRes.cleanedQueryText());
    }

    @Test
    @DisplayName("Extracts and classifies single and multiple URLs in message")
    void testPhishingUrlClassification() {
        BotMessageRequest singleUrl = new BotMessageRequest("WHATSAPP", "+123", "Check your account at https://secure-bank-login.xyz/auth");
        MessageIntentClassifier.IntentResult result1 = classifier.classify(singleUrl);

        assertEquals(MessageIntentClassifier.IntentType.PHISHING_URL, result1.intentType());
        assertEquals(1, result1.extractedUrls().size());
        assertEquals("https://secure-bank-login.xyz/auth", result1.extractedUrls().getFirst());

        BotMessageRequest multiUrl = new BotMessageRequest("WEB_CHAT", "web1", "Compare http://example.com with phishing.top/login");
        MessageIntentClassifier.IntentResult result2 = classifier.classify(multiUrl);
        assertEquals(MessageIntentClassifier.IntentType.PHISHING_URL, result2.intentType());
        assertEquals(2, result2.extractedUrls().size());
    }

    @Test
    @DisplayName("Classifies viral news and forwarded text as VIRAL_CLAIM")
    void testViralClaimClassification() {
        BotMessageRequest viralMsg = new BotMessageRequest(
                "WHATSAPP",
                "+123",
                "Forwarded many times: UNESCO has just declared the Indian national anthem the best in the world!"
        );
        MessageIntentClassifier.IntentResult result = classifier.classify(viralMsg);

        assertEquals(MessageIntentClassifier.IntentType.VIRAL_CLAIM, result.intentType());
        assertTrue(result.cleanedQueryText().contains("UNESCO"));
    }

    @Test
    @DisplayName("Classifies media attachments as MULTIMODAL_MEDIA")
    void testMediaClassification() {
        BotMessageRequest mediaMsg = new BotMessageRequest(
                IncidentId.generate(),
                "WHATSAPP",
                "+123",
                "Is this minister video real?",
                "VIDEO",
                "AAAAIGZ0eXBtcDQyAAAAAG1wNDJpc29t...",
                "speech.mp4"
        );
        MessageIntentClassifier.IntentResult result = classifier.classify(mediaMsg);

        assertEquals(MessageIntentClassifier.IntentType.MULTIMODAL_MEDIA, result.intentType());
        assertEquals("speech.mp4", mediaMsg.mediaFilename());
    }

    @Test
    @DisplayName("Classifies password checks as PASSWORD_BREACH")
    void testPasswordBreachClassification() {
        BotMessageRequest pwdMsg = new BotMessageRequest("TELEGRAM", "tg1", "password: MySuperSecretPassword123!");
        MessageIntentClassifier.IntentResult result = classifier.classify(pwdMsg);

        assertEquals(MessageIntentClassifier.IntentType.PASSWORD_BREACH, result.intentType());
        assertEquals("MySuperSecretPassword123!", result.cleanedQueryText());

        BotMessageRequest checkPwd = new BotMessageRequest("WEB_CHAT", "u1", "check password Password12345");
        MessageIntentClassifier.IntentResult checkRes = classifier.classify(checkPwd);
        assertEquals(MessageIntentClassifier.IntentType.PASSWORD_BREACH, checkRes.intentType());
    }

    @Test
    @DisplayName("Falls back to GENERAL_SAFETY for short greetings")
    void testGeneralSafetyFallback() {
        BotMessageRequest greeting = new BotMessageRequest("WHATSAPP", "+123", "Hello bot");
        MessageIntentClassifier.IntentResult result = classifier.classify(greeting);

        assertEquals(MessageIntentClassifier.IntentType.GENERAL_SAFETY, result.intentType());
    }
}
