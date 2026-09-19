package com.trustshield.breach.offline;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import jakarta.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import com.trustshield.breach.config.BreachProperties;
import com.trustshield.breach.hibp.BreachLookupResult;
import com.trustshield.common.util.HashUtils;

/**
 * Offline membership check against a bundled list of well-known weak passwords.
 *
 * <p><strong>Why this exists.</strong> The Pwned Passwords range API is the real
 * source, but it needs connectivity. A demo that depends on a network call can
 * fail in front of an examiner, so the service ships a small local list and
 * always consults it. The two sources are complementary: the API is
 * authoritative, this is merely always available.
 *
 * <h2>Honesty constraints baked into this class</h2>
 *
 * <ul>
 *   <li>A match returns {@link BreachLookupResult#exposedCountUnknown} — never a
 *       count. This source knows membership only, and inventing an occurrence
 *       figure would be fabricating a statistic.</li>
 *   <li>A miss returns {@code UNAVAILABLE}, not {@code NOT_FOUND}. With a list
 *       this short, absence carries almost no information, and reporting it as
 *       "not found" would invite the reader to treat it as "safe". The
 *       distinction is enforced here rather than left to the caller.</li>
 * </ul>
 *
 * <p>Only SHA-1 digests are retained in memory; the plaintext lines are
 * discarded after loading. The source file stays plaintext on disk so it can be
 * audited — see the header comment in {@code common-passwords.txt}.
 */
@Component
public class CommonPasswordCatalog {

    private static final Logger log = LoggerFactory.getLogger(CommonPasswordCatalog.class);

    public static final String SOURCE = "BUNDLED_COMMON_PASSWORD_LIST";

    private final ResourceLoader resourceLoader;
    private final String catalogPath;

    /** Upper-case hex SHA-1 digests of every catalog entry. */
    private Set<String> digests = Set.of();

    public CommonPasswordCatalog(ResourceLoader resourceLoader, BreachProperties properties) {
        this.resourceLoader = resourceLoader;
        this.catalogPath = properties.offlineCatalogPath();
    }

    @PostConstruct
    void load() {
        Resource resource = resourceLoader.getResource(catalogPath);
        if (!resource.exists()) {
            // Degrade rather than refuse to start: the API path may still work.
            log.warn("Common-password catalog not found at {}. Offline checks will report UNAVAILABLE.",
                    catalogPath);
            return;
        }

        Set<String> loaded = new HashSet<>();
        try (InputStream in = resource.getInputStream();
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(in, StandardCharsets.UTF_8))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String entry = line.strip();
                if (entry.isEmpty() || entry.startsWith("#")) {
                    continue;
                }
                loaded.add(HashUtils.sha1HexUpper(entry));
            }
        } catch (IOException e) {
            log.warn("Failed to read common-password catalog: {}", e.getMessage());
            return;
        }

        this.digests = Set.copyOf(loaded);
        log.info("Loaded {} common-password digests for offline breach checks", digests.size());
    }

    public int size() {
        return digests.size();
    }

    /**
     * Checks a password against the bundled list.
     *
     * @param password never logged, never stored, never transmitted
     * @return {@code EXPOSED} with no count on a hit; {@code UNAVAILABLE} on a
     *         miss, because this list is too small for absence to be meaningful
     */
    public BreachLookupResult check(String password) {
        if (password == null || password.isEmpty()) {
            return BreachLookupResult.unavailable(SOURCE, "Empty password");
        }
        if (digests.isEmpty()) {
            return BreachLookupResult.unavailable(SOURCE, "Catalog unavailable");
        }
        if (digests.contains(HashUtils.sha1HexUpper(password))) {
            return BreachLookupResult.exposedCountUnknown(SOURCE);
        }
        return BreachLookupResult.unavailable(SOURCE,
                "Not in the bundled list, which contains only " + digests.size()
                        + " entries, too few for absence to indicate safety");
    }
}
