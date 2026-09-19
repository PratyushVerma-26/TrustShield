package com.trustshield.fakenews.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InternetFactCheckDirectoryClientTest {

    private InternetFactCheckDirectoryClient client;

    @BeforeEach
    void setUp() {
        // Disabled external API to verify offline directory invariants
        client = new InternetFactCheckDirectoryClient(false, "https://factchecktools.googleapis.com/v1alpha1/claims:search", 1000);
    }

    @Test
    @DisplayName("Queries bundled debunk directory for viral NASA darkness hoax")
    void identifiesBundledNasaDarknessHoax() {
        String claim = "NASA confirms 15 days of total worldwide darkness in November";
        var result = client.queryDirectories(claim);

        assertNotNull(result);
        assertTrue(result.consulted());
        assertTrue(result.matchFound());
        assertTrue(result.sourceName().contains("Snopes") || result.sourceName().contains("NASA"));
        assertNotNull(result.reviewUrl());
    }

    @Test
    @DisplayName("Queries bundled debunk directory for dangerous bleach cure hoax")
    void identifiesBundledBleachHoax() {
        String claim = "Drinking bleach or chlorine dioxide cures COVID-19 infection";
        var result = client.queryDirectories(claim);

        assertTrue(result.consulted());
        assertTrue(result.matchFound());
        assertTrue(result.textualRating().toLowerCase().contains("dangerous") || result.textualRating().toLowerCase().contains("hoax"));
    }

    @Test
    @DisplayName("Queries bundled debunk directory for Pentagon explosion hoax")
    void identifiesBundledPentagonHoax() {
        String claim = "Breaking news Pentagon explosion smoke plume near headquarters";
        var result = client.queryDirectories(claim);

        assertTrue(result.consulted());
        assertTrue(result.matchFound());
        assertEquals("Reuters Fact Check & Arlington Fire Dept", result.sourceName());
    }

    @Test
    @DisplayName("Unindexed claim returns unavailable when external directory is disabled")
    void unindexedClaimReturnsUnavailableOffline() {
        String claim = "City council announces new public park schedule for the summer season";
        var result = client.queryDirectories(claim);

        assertFalse(result.consulted());
        assertFalse(result.matchFound());
    }
}
