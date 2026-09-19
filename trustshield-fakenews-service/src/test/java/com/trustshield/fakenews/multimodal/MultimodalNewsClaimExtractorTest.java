package com.trustshield.fakenews.multimodal;

import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultimodalNewsClaimExtractorTest {

    private MultimodalNewsClaimExtractor extractor;
    private NewsSourceCredibilityDirectory directory;

    @BeforeEach
    void setUp() {
        directory = new NewsSourceCredibilityDirectory();
        NewsChyronAnalyzer chyronAnalyzer = new NewsChyronAnalyzer(0.65);
        extractor = new MultimodalNewsClaimExtractor(chyronAnalyzer, directory);
    }

    @Test
    @DisplayName("Plain text request bypasses media decoding and detects source domain if present")
    void plainTextRequestHandledGracefully() {
        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "Scientists report breakthrough in solar cell efficiency according to reuters.com article",
                "WEB"
        );

        var result = extractor.extractClaim(request);

        assertNotNull(result);
        assertFalse(result.extraction().mediaProcessed());
        assertEquals("TEXT", result.extraction().mediaType());
        assertEquals("reuters.com", result.detectedSourceDomain());
        assertEquals(request.claimText(), result.effectiveClaimText());
    }

    @Test
    @DisplayName("Extracts video title from simulated MP4 nam atom payload")
    void extractsVideoTitleAtom() {
        // Build simulated container segment with ©nam atom
        byte[] atomTag = "\u00a9nam".getBytes(StandardCharsets.ISO_8859_1);
        byte[] titleContent = "Exclusive Interview: Prime Minister addresses national economic summit".getBytes(StandardCharsets.UTF_8);

        byte[] payload = new byte[32 + atomTag.length + titleContent.length];
        System.arraycopy(atomTag, 0, payload, 16, atomTag.length);
        System.arraycopy(titleContent, 0, payload, 16 + atomTag.length, titleContent.length);

        String base64 = Base64.getEncoder().encodeToString(payload);
        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "", // empty text: extractor should promote video title
                "BROADCAST",
                "VIDEO",
                base64,
                "broadcast_segment.mp4",
                "video/mp4"
        );

        var result = extractor.extractClaim(request);

        assertTrue(result.extraction().mediaProcessed());
        assertEquals("VIDEO", result.extraction().mediaType());
        assertNotNull(result.extraction().extractedHeadline());
        assertTrue(result.extraction().extractedHeadline().contains("Prime Minister"));
        assertEquals(result.extraction().extractedHeadline(), result.effectiveClaimText());
    }

    @Test
    @DisplayName("Detects satirical domain from context URL")
    void detectsSatireDomainFromContext() {
        ClaimCheckRequest request = new ClaimCheckRequest(
                IncidentId.generate(),
                "Nation's Dogs Demand Equal Representation in Congress",
                "https://www.theonion.com/article-12345"
        );

        var result = extractor.extractClaim(request);

        assertEquals("theonion.com", result.detectedSourceDomain());
    }
}
