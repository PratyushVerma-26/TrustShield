package com.trustshield.fakenews.simhash;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.common.dto.ClaimCheckResponse.SimHashMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DebunkedClaimCatalogTest {

    private DebunkedClaimCatalog catalog;

    @BeforeEach
    void setUp() {
        catalog = new DebunkedClaimCatalog(
                new ClassPathResource("misinformation/debunked_claims.json"),
                0.78,
                new ObjectMapper()
        );
        catalog.init();
    }

    @Test
    @DisplayName("Catalog initializes with bundled debunked claims")
    void catalogInitialization() {
        assertTrue(catalog.getEntryCount() >= 20, "Catalog should have at least 20 entries");
        assertNotNull(catalog.getEntries().get(0).debunkTitle());
    }

    @Test
    @DisplayName("Exact match against cataloged debunked claim returns matched=true")
    void exactMatch() {
        String claim = "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world";
        SimHashMatch match = catalog.findBestMatch(claim);

        assertTrue(match.matched());
        assertEquals(1.0, match.similarity(), 0.01);
        assertNotNull(match.matchedClaim());
        assertNotNull(match.debunkSourceUrl());
    }

    @Test
    @DisplayName("Near-duplicate viral forward matches bundled debunked claim")
    void nearDuplicateForwardMatch() {
        String forward = "URGENT FORWARD: UNESCO has declared Indian national anthem Jana Gana Mana best in world! Forward to all groups.";
        SimHashMatch match = catalog.findBestMatch(forward);

        assertTrue(match.matched(), "Should match near-duplicate hoax forward");
        assertTrue(match.similarity() >= 0.78, "Similarity should meet threshold: " + match.similarity());
    }

    @Test
    @DisplayName("Unrelated text yields no match without errors")
    void unrelatedTextNoMatch() {
        String neutralText = "The Reserve Bank of India announced the bi-monthly monetary policy committee decisions today.";
        SimHashMatch match = catalog.findBestMatch(neutralText);

        assertFalse(match.matched());
        assertEquals(0.0, match.similarity());
    }
}
