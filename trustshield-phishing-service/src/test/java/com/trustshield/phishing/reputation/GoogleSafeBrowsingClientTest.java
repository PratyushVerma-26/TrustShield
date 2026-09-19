package com.trustshield.phishing.reputation;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GoogleSafeBrowsingClientTest {

    private GoogleSafeBrowsingClient client;

    @BeforeEach
    void setUp() {
        client = new GoogleSafeBrowsingClient(new ObjectMapper());
    }

    @Test
    @DisplayName("reports disabled when no API key is configured")
    void disabledWhenNoKey() {
        ReflectionTestUtils.setField(client, "enabled", true);
        ReflectionTestUtils.setField(client, "apiKey", "");

        assertFalse(client.isEnabled());

        ReputationVerdict verdict = client.check("https://example.com");
        assertFalse(verdict.available());
        assertEquals("No API key configured", verdict.detail());
    }

    @Test
    @DisplayName("reports disabled when enabled flag is false even if key is present")
    void disabledWhenFlagFalse() {
        ReflectionTestUtils.setField(client, "enabled", false);
        ReflectionTestUtils.setField(client, "apiKey", "test-key-123");

        assertFalse(client.isEnabled());

        ReputationVerdict verdict = client.check("https://example.com");
        assertFalse(verdict.available());
    }

    @Test
    @DisplayName("reports enabled when flag is true and key is non-blank")
    void enabledWhenFlagTrueAndKeyPresent() {
        ReflectionTestUtils.setField(client, "enabled", true);
        ReflectionTestUtils.setField(client, "apiKey", "AIzaSyTestKey123");

        assertTrue(client.isEnabled());
        assertEquals("GOOGLE_SAFE_BROWSING", client.name());
    }
}
