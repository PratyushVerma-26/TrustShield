package com.trustshield.breach.offline;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import com.trustshield.breach.config.BreachProperties;
import com.trustshield.breach.hibp.BreachLookupResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the bundled offline catalog.
 *
 * <p>Two of these assertions are about honesty rather than correctness, and both
 * would pass just as happily if the class lied. They are here because the lies
 * are tempting: inventing an occurrence count makes the UI look richer, and
 * reporting a miss as {@code NOT_FOUND} makes the verdict look more confident.
 */
class CommonPasswordCatalogTest {

    private CommonPasswordCatalog catalog;

    private static CommonPasswordCatalog catalogAt(String path) {
        CommonPasswordCatalog c = new CommonPasswordCatalog(
                new DefaultResourceLoader(),
                new BreachProperties(path, 0L, null, null));
        c.load();
        return c;
    }

    @BeforeEach
    void setUp() {
        catalog = catalogAt("classpath:breach/common-passwords.txt");
    }

    @Test
    @DisplayName("the bundled catalog loads")
    void loadsCatalog() {
        assertTrue(catalog.size() > 100,
                "expected the bundled list to load, got " + catalog.size() + " entries");
    }

    @Test
    @DisplayName("a known weak password is reported EXPOSED with no network")
    void knownWeakPassword() {
        // This is the demo path: no connectivity, no API key, real EXPOSED verdict.
        BreachLookupResult result = catalog.check("password123");
        assertEquals(BreachLookupResult.Status.EXPOSED, result.status());
        assertTrue(result.isExposed());
        assertEquals(CommonPasswordCatalog.SOURCE, result.source());
    }

    @Test
    @DisplayName("a hit reports no occurrence count, because this source has none")
    void hitCarriesNoInventedCount() {
        BreachLookupResult result = catalog.check("password123");
        assertTrue(result.occurrences().isEmpty(),
                "a membership-only source must not report a frequency it does not have");
        assertTrue(result.detail().contains("does not report counts"));
    }

    /**
     * The important one.
     *
     * <p>With a list of a few hundred entries, a miss means almost nothing — the
     * password is simply not one of the most obvious few hundred. Reporting
     * {@code NOT_FOUND} would invite the caller, and then the user, to read that as
     * "checked and clean". So absence is reported as {@code UNAVAILABLE}, which the
     * scoring layer already knows to treat as "unknown" and to mark the verdict
     * degraded.
     */
    @Test
    @DisplayName("a miss is UNAVAILABLE, not NOT_FOUND")
    void missIsUnavailableNotNotFound() {
        BreachLookupResult result = catalog.check("Xq7#vLm2$pRt9wZk");
        assertEquals(BreachLookupResult.Status.UNAVAILABLE, result.status(),
                "a list this small cannot support a claim of absence");
        assertFalse(result.isExposed());
        assertTrue(result.detail().contains("too few for absence to indicate safety"));
    }

    @Test
    @DisplayName("a missing catalog file degrades instead of failing startup")
    void missingCatalogDegrades() {
        CommonPasswordCatalog missing = catalogAt("classpath:breach/does-not-exist.txt");
        assertEquals(0, missing.size());
        assertEquals(BreachLookupResult.Status.UNAVAILABLE,
                missing.check("password123").status(),
                "with no catalog loaded, even a known-weak password must be UNAVAILABLE");
    }

    @Test
    @DisplayName("empty and null inputs are unavailable rather than matched")
    void emptyInput() {
        assertEquals(BreachLookupResult.Status.UNAVAILABLE, catalog.check("").status());
        assertEquals(BreachLookupResult.Status.UNAVAILABLE, catalog.check(null).status());
    }

    @Test
    @DisplayName("matching is exact, not case-insensitive or fuzzy")
    void matchingIsExact() {
        // The catalog stores SHA-1 digests, so matching is necessarily exact. That
        // is a limitation worth knowing: "Password123" and "password123" are
        // separate entries and both happen to be listed, but "PASSWORD123" is not.
        assertEquals(BreachLookupResult.Status.EXPOSED, catalog.check("password123").status());
        assertEquals(BreachLookupResult.Status.EXPOSED, catalog.check("Password123").status());
        assertEquals(BreachLookupResult.Status.UNAVAILABLE, catalog.check("PASSWORD123").status(),
                "digest matching cannot generalise across case; the range API is the "
                        + "source that actually has coverage");
    }
}
