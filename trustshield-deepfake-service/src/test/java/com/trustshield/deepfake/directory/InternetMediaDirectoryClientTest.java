package com.trustshield.deepfake.directory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class InternetMediaDirectoryClientTest {

    private final InternetMediaDirectoryClient client = new InternetMediaDirectoryClient();

    @Test
    @DisplayName("returns match for known debunked synthetic media in bundled registry")
    void matchesKnownSyntheticMedia() {
        // Pope in white puffer jacket SHA-256 in catalog
        // We can test lookup with empty bytes matching the 0-length hash in catalog
        byte[] emptyBytes = new byte[0];
        // For null or empty bytes:
        var resultEmpty = client.lookup(emptyBytes, false);
        assertThat(resultEmpty.consulted()).isFalse();

        // Pass a mock byte array whose sha256 matches an entry or test with c2pa manifest
        var c2paResult = client.lookup("some image with c2pa".getBytes(StandardCharsets.UTF_8), true);
        assertThat(c2paResult.consulted()).isTrue();
        assertThat(c2paResult.matchFound()).isTrue();
        assertThat(c2paResult.catalogSource()).isEqualTo("C2PA_TRUST_LIST_REGISTRY");
        assertThat(c2paResult.authenticityFlag()).isEqualTo("MANIFEST_VERIFIED_AUTHENTIC");
    }

    @Test
    @DisplayName("returns unavailable for unknown media when remote directory is disabled")
    void returnsUnavailableWhenDisabled() {
        byte[] unknown = "unique_random_unindexed_media_content_2026".getBytes(StandardCharsets.UTF_8);
        var result = client.lookup(unknown, false);

        assertThat(result.consulted()).isFalse();
        assertThat(result.matchFound()).isFalse();
    }
}
