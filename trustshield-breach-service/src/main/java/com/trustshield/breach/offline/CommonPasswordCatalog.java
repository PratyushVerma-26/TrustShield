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
 * Offline membership verification against a bundled catalog of known weak passwords.
 *
 * <p>Provides immediate, zero-latency local fallback capability alongside
 * the k-anonymous Pwned Passwords range API.
 *
 * <p>Key properties:
 * <ul>
 *   <li>A match returns {@link BreachLookupResult#exposedCountUnknown}; frequency counts
 *       are not fabricated since this source only verifies set membership.</li>
 *   <li>A non-match returns {@code UNAVAILABLE} rather than {@code NOT_FOUND}, since a small
 *       offline catalog cannot verify absence across global breach corpora.</li>
 * </ul>
 *
 * <p>Only SHA-1 digests are stored in memory; plaintext entries are discarded
 * immediately after catalog ingestion.
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
