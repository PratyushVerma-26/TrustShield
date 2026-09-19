package com.trustshield.fakenews.simhash;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.common.dto.ClaimCheckResponse.SimHashMatch;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Offline catalog of verified debunked claims and hoaxes.
 *
 * <p>Loads bundled claims at startup and precomputes 64-bit SimHash fingerprints
 * to enable sub-millisecond near-duplicate lookup during offline or disconnected runs.
 *
 * <p>Invariant: Like the 138-password catalog in the breach service, a match is strong
 * evidence of known misinformation, while a miss means almost nothing (the claim is merely
 * unindexed in this catalog) and must NOT be interpreted as proof of factual truth.
 */
@Component
public class DebunkedClaimCatalog {

    private static final Logger log = LoggerFactory.getLogger(DebunkedClaimCatalog.class);

    private final Resource catalogResource;
    private final ObjectMapper objectMapper;
    private final double similarityThreshold;
    private final List<CatalogEntry> entries = new ArrayList<>();

    public DebunkedClaimCatalog(
            @Value("${trustshield.fakenews.simhash.catalog-path:classpath:misinformation/debunked_claims.json}") Resource catalogResource,
            @Value("${trustshield.fakenews.simhash.similarity-threshold:0.78}") double similarityThreshold,
            ObjectMapper objectMapper) {
        this.catalogResource = catalogResource;
        this.similarityThreshold = similarityThreshold;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        try (InputStream is = catalogResource.getInputStream()) {
            List<RawDebunkedClaim> rawList = objectMapper.readValue(is, new TypeReference<>() {});
            for (RawDebunkedClaim raw : rawList) {
                long hash = SimHashMatcher.computeHash(raw.claim());
                entries.add(new CatalogEntry(
                        raw.id(),
                        raw.claim(),
                        raw.claimant(),
                        raw.debunkTitle(),
                        raw.debunkSource(),
                        raw.debunkUrl(),
                        raw.category(),
                        hash
                ));
            }
            log.info("Initialized DebunkedClaimCatalog with {} precomputed entries (threshold={})",
                    entries.size(), similarityThreshold);
        } catch (Exception e) {
            log.warn("Failed to load debunked claims catalog from {}: {}. Offline matching disabled.",
                    catalogResource, e.getMessage());
        }
    }

    /**
     * Finds the closest matching debunked claim via 64-bit SimHash Hamming similarity.
     *
     * @param claimText the input claim text
     * @return SimHashMatch object containing match status, matched claim, similarity, and debunk source
     */
    public SimHashMatch findBestMatch(String claimText) {
        return findBestMatch(claimText, this.similarityThreshold);
    }

    /**
     * Finds the closest matching debunked claim with custom similarity threshold.
     */
    public SimHashMatch findBestMatch(String claimText, double threshold) {
        if (claimText == null || claimText.isBlank() || entries.isEmpty()) {
            return SimHashMatch.none();
        }

        long inputHash = SimHashMatcher.computeHash(claimText);
        if (inputHash == 0L) {
            return SimHashMatch.none();
        }

        CatalogEntry bestEntry = null;
        double bestSimilarity = 0.0;

        for (CatalogEntry entry : entries) {
            double sim = SimHashMatcher.similarity(inputHash, entry.simHash());
            if (sim > bestSimilarity) {
                bestSimilarity = sim;
                bestEntry = entry;
            }
        }

        if (bestEntry != null && bestSimilarity >= threshold) {
            return new SimHashMatch(
                    true,
                    bestEntry.claim(),
                    Math.round(bestSimilarity * 100.0) / 100.0,
                    bestEntry.debunkUrl()
            );
        }

        return SimHashMatch.none();
    }

    public List<CatalogEntry> getEntries() {
        return Collections.unmodifiableList(entries);
    }

    public int getEntryCount() {
        return entries.size();
    }

    public record CatalogEntry(
            String id,
            String claim,
            String claimant,
            String debunkTitle,
            String debunkSource,
            String debunkUrl,
            String category,
            long simHash
    ) {}

    private record RawDebunkedClaim(
            String id,
            String claim,
            String claimant,
            String debunkTitle,
            String debunkSource,
            String debunkUrl,
            String category
    ) {}
}
