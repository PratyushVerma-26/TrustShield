package com.trustshield.fakenews.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse;
import com.trustshield.common.dto.ClaimCheckResponse.FactCheckResult;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.fakenews.client.GoogleFactCheckClient;
import com.trustshield.fakenews.simhash.DebunkedClaimCatalog;
import com.trustshield.fakenews.style.LinguisticStyleAnalyzer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class ClaimVerificationOrchestratorTest {

    private GoogleFactCheckClient mockFactCheckClient;
    private DebunkedClaimCatalog catalog;
    private LinguisticStyleAnalyzer styleAnalyzer;
    private ClaimVerificationOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        mockFactCheckClient = Mockito.mock(GoogleFactCheckClient.class);
        catalog = new DebunkedClaimCatalog(
                new ClassPathResource("misinformation/debunked_claims.json"),
                0.82,
                new ObjectMapper()
        );
        catalog.init();
        styleAnalyzer = new LinguisticStyleAnalyzer(55);
        orchestrator = new ClaimVerificationOrchestrator(mockFactCheckClient, catalog, styleAnalyzer);
    }

    @Test
    @DisplayName("SimHash near-duplicate match floors score >= 85 and marks DANGEROUS")
    void simHashMatchElevatesToDangerous() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        String hoax = "UNESCO declares Indian national anthem Jana Gana Mana as best national anthem in the world";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), hoax, "WHATSAPP_FORWARD");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertNotNull(response);
        assertTrue(response.simHashMatch().matched());
        assertEquals(ThreatLevel.DANGEROUS, response.verdict().threatLevel());
        assertTrue(response.verdict().riskScore() >= 85);
        assertEquals("SIMHASH_NEAR_DUPLICATE_DEBUNKED", response.verdict().verdict());
        assertFalse(response.verdict().degraded());
    }

    @Test
    @DisplayName("Fact check API match sets DANGEROUS with FACT_CHECK_CORROBORATION")
    void factCheckMatchSetsDangerous() {
        FactCheckResult factCheckHit = new FactCheckResult(
                true,
                true,
                "Social Media Post",
                "False claim regarding 5G towers and viral infection",
                "https://factcheck.example.com/5g",
                "False",
                "Reuters Fact Check"
        );
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(factCheckHit);

        String text = "Unrelated claim about 5G towers and health effects";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), text, "TWITTER");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.DANGEROUS, response.verdict().threatLevel());
        assertTrue(response.verdict().riskScore() >= 90);
        assertEquals("FACT_CHECK_CORROBORATION", response.verdict().verdict());
        assertTrue(response.verdict().explanation().contains("Reuters Fact Check"));
    }

    @Test
    @DisplayName("Crucial Invariant: Disabled API and no debunked match returns UNKNOWN (not SAFE)")
    void unverifiedClaimReturnsUnknown() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        String neutralUnindexedClaim = "Local council approves construction of new community playground in Sector 4";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), neutralUnindexedClaim, "LOCAL_NEWS");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        // Crucial invariant: Never say SAFE when nothing was checked!
        assertEquals(ThreatLevel.UNKNOWN, response.verdict().threatLevel());
        assertEquals(0, response.verdict().riskScore());
        assertTrue(response.verdict().degraded());
        assertEquals("NO_SOURCES_CONSULTED", response.verdict().verdict());
    }

    @Test
    @DisplayName("Disabled API with sensational style caps at SUSPICIOUS and marks degraded")
    void unverifiedSensationalClaimCapsAtSuspicious() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        String breathlessText = "URGENT BREAKING NEWS! Sources say secret documents prove shocking hidden agenda! Share now!!";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), breathlessText, "WHATSAPP_FORWARD");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.SUSPICIOUS, response.verdict().threatLevel());
        assertTrue(response.verdict().riskScore() <= 55, "Score must not exceed 55");
        assertTrue(response.verdict().degraded());
        assertEquals("SENSATIONALIST_STYLE_CORRELATION", response.verdict().verdict());
    }

    @Test
    @DisplayName("Consulted Fact Check API with no matches and calm style returns SAFE without degradation")
    void consultedNoMatchReturnsSafe() {
        FactCheckResult cleanFactCheck = new FactCheckResult(true, false, null, null, null, null, null);
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(cleanFactCheck);

        String calmText = "The state library will remain closed on national holidays according to the annual calendar.";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), calmText, "PUBLIC_ANNOUNCEMENT");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.SAFE, response.verdict().threatLevel());
        assertFalse(response.verdict().degraded());
        assertEquals("NO_FACT_CHECK_CONCERNS", response.verdict().verdict());
    }

    @Test
    @DisplayName("Claim originating from satirical news outlet is classified as DANGEROUS/SATIRICAL_NEWS_CONTENT")
    void satireSourceDetectedEscalatesToDangerous() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "Congress Votes To Replace All Laws With One Big Law",
                "https://www.theonion.com/congress-votes-to-replace-all-laws-1849"
        );

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.DANGEROUS, response.verdict().threatLevel());
        assertEquals(85, response.verdict().riskScore());
        assertEquals("SATIRICAL_NEWS_CONTENT", response.verdict().verdict());
        assertFalse(response.verdict().degraded());
    }

    @Test
    @DisplayName("Claim originating from known disinformation domain is classified as DANGEROUS/DISINFORMATION_PROPAGANDA_OUTLET")
    void disinformationSourceDetectedEscalatesToDangerous() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "Shocking discovery confirms prehistoric giants inhabited remote valley",
                "http://worldnewsdailyreport.com/giants-found"
        );

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.DANGEROUS, response.verdict().threatLevel());
        assertTrue(response.verdict().riskScore() >= 90);
        assertEquals("DISINFORMATION_PROPAGANDA_OUTLET", response.verdict().verdict());
    }

    @Test
    @DisplayName("Internet directory match floors risk score >= 90 with INTERNET_DIRECTORY_DEBUNKED")
    void internetDirectoryDebunkFloorsScoreAtDangerous() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        String claim = "Drinking bleach or chlorine dioxide cures COVID-19 infection";
        ClaimCheckRequest request = new ClaimCheckRequest(IncidentId.generate(), claim, "WHATSAPP");

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertEquals(ThreatLevel.DANGEROUS, response.verdict().threatLevel());
        assertTrue(response.verdict().riskScore() >= 90);
        assertTrue(response.directoryResult().matchFound());
    }

    @Test
    @DisplayName("Reputable mainstream news outlet with calm text evaluates as VERIFIED_REPUTABLE_SOURCE")
    void trustedMainstreamSourceEvaluatesAsReputable() {
        when(mockFactCheckClient.searchClaim(anyString())).thenReturn(FactCheckResult.unavailable());

        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "Central bank maintains baseline interest rates following quarterly economic review",
                "https://www.reuters.com/markets/central-bank-rates"
        );

        ClaimCheckResponse response = orchestrator.verifyClaim(request);

        assertTrue(response.verdict().riskScore() <= 25);
        assertEquals(ThreatLevel.SAFE, response.verdict().threatLevel());
        assertEquals("VERIFIED_REPUTABLE_SOURCE", response.verdict().verdict());
    }
}
