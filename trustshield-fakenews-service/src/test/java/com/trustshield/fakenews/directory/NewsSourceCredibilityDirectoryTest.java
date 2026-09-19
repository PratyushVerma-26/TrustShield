package com.trustshield.fakenews.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NewsSourceCredibilityDirectoryTest {

    private NewsSourceCredibilityDirectory directory;

    @BeforeEach
    void setUp() {
        directory = new NewsSourceCredibilityDirectory();
    }

    @Test
    @DisplayName("Mainstream reputable news wire agencies are classified as TRUSTED_MAINSTREAM")
    void recognizesTrustedMainstreamOutlets() {
        var reuters = directory.evaluateSource("https://www.reuters.com/world/article123");
        assertTrue(reuters.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.TRUSTED_MAINSTREAM, reuters.category());
        assertTrue(reuters.credibilityScore() >= 90);
        assertTrue(reuters.riskScore() <= 10);

        var bbc = directory.evaluateSource("bbc.co.uk");
        assertTrue(bbc.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.TRUSTED_MAINSTREAM, bbc.category());

        var ap = directory.evaluateSource("apnews.com");
        assertTrue(ap.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.TRUSTED_MAINSTREAM, ap.category());
    }

    @Test
    @DisplayName("Recognized satirical websites are classified as SATIRE_PARODY")
    void recognizesSatiricalOutlets() {
        var onion = directory.evaluateSource("https://www.theonion.com/study-finds-aliens-1849");
        assertTrue(onion.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.SATIRE_PARODY, onion.category());
        assertEquals(85, onion.riskScore());

        var babylon = directory.evaluateSource("babylonbee.com");
        assertTrue(babylon.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.SATIRE_PARODY, babylon.category());

        var fauxy = directory.evaluateSource("thefauxy.com");
        assertTrue(fauxy.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.SATIRE_PARODY, fauxy.category());
    }

    @Test
    @DisplayName("Known disinformation and fake news sites are classified as KNOWN_MISINFO_PROPAGANDA")
    void recognizesDisinformationOutlets() {
        var wndr = directory.evaluateSource("worldnewsdailyreport.com");
        assertTrue(wndr.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.KNOWN_MISINFO_PROPAGANDA, wndr.category());
        assertTrue(wndr.riskScore() >= 90);

        var infowars = directory.evaluateSource("infowars.com");
        assertTrue(infowars.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.KNOWN_MISINFO_PROPAGANDA, infowars.category());

        var naturalNews = directory.evaluateSource("naturalnews.com");
        assertTrue(naturalNews.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.KNOWN_MISINFO_PROPAGANDA, naturalNews.category());
    }

    @Test
    @DisplayName("Unindexed or personal domains return UNKNOWN with neutral baseline")
    void unindexedDomainReturnsUnknown() {
        var unknown = directory.evaluateSource("https://my-local-neighborhood-blog.net/post");
        assertFalse(unknown.isKnownSource());
        assertEquals(NewsSourceCredibilityDirectory.SourceCategory.UNKNOWN, unknown.category());
        assertEquals(0, unknown.riskScore());
    }

    @Test
    @DisplayName("Domain normalization correctly handles protocol, subdomains, and trailing paths")
    void extractsDomainAccurately() {
        assertEquals("reuters.com", directory.extractDomain("https://www.reuters.com/business/finance"));
        assertEquals("theonion.com", directory.extractDomain("http://theonion.com/article?id=123"));
        assertEquals("bbc.co.uk", directory.extractDomain("www.bbc.co.uk:8080/news"));
    }
}
