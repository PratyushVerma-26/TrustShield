package com.trustshield.phishing.ml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Proves the Java extractor and the Python training script compute the same
 * features for the same URLs.
 *
 * <h2>Why this test exists</h2>
 *
 * <p>The model's coefficients are learned in Python and applied in Java. If the
 * two implementations of feature extraction drift apart — a different entropy
 * base, a different brand list, one counting hyphens in the host and the other in
 * the whole URL — then coefficients get multiplied by the wrong quantities. This
 * failure mode is called training/serving skew and it is unusually nasty: nothing
 * throws, no log line appears, and the service returns confidently wrong verdicts
 * with a plausible-looking explanation attached. Accuracy measured in Python
 * would stay excellent while the deployed system quietly degraded.
 *
 * <p>The only reliable defence is to pin both implementations to shared fixtures.
 * {@code train_phishing_model.py} writes the vectors it computes for a set of
 * URLs, including deliberately awkward ones, and this test asserts the Java
 * extractor reproduces them.
 *
 * <h2>If this test is skipped</h2>
 *
 * <p>The fixtures are a training artefact, so they are absent until the model has
 * been trained at least once. The test skips rather than fails in that case, and
 * says how to produce them. A skip means parity is <em>unverified</em>, not
 * verified — worth knowing before quoting any accuracy figure.
 */
class UrlFeatureExtractorParityTest {

    private static final String FIXTURES = "/parity_fixtures.json";

    /** Fixtures are rounded to 8 decimal places on the Python side. */
    private static final double TOLERANCE = 1e-6;

    @Test
    @DisplayName("Java and Python extractors agree on every fixture URL")
    void extractorsAgree() throws Exception {
        JsonNode root;
        try (InputStream in = getClass().getResourceAsStream(FIXTURES)) {
            assumeTrue(in != null, () -> """
                    Parity fixtures not found on the test classpath.
                    Parity between the Python and Java feature extractors is therefore
                    UNVERIFIED. To generate them:
                        python scripts/train_phishing_model.py --data data/urls.csv
                        cp parity_fixtures.json trustshield-phishing-service/src/test/resources/
                    """);
            root = new ObjectMapper().readTree(in);
        }

        // 1. Feature order must match, or every subsequent comparison is meaningless.
        JsonNode names = root.path("featureNames");
        assertEquals(UrlFeatureExtractor.FEATURE_NAMES.length, names.size(),
                "Fixture feature count differs from the Java extractor");
        for (int i = 0; i < UrlFeatureExtractor.FEATURE_NAMES.length; i++) {
            assertEquals(UrlFeatureExtractor.FEATURE_NAMES[i], names.get(i).asText(),
                    "Feature name mismatch at index " + i
                            + " -- the Python and Java extractors have diverged");
        }

        // 2. Every fixture vector must match element by element.
        JsonNode cases = root.path("cases");
        assertTrue(cases.isArray() && !cases.isEmpty(), "Fixture file contains no cases");

        for (JsonNode testCase : cases) {
            final String url = testCase.path("url").asText();
            JsonNode expected = testCase.path("features");
            double[] actual = UrlFeatureExtractor.extract(url);

            assertEquals(expected.size(), actual.length,
                    "Vector length mismatch for URL: " + url);

            for (int i = 0; i < actual.length; i++) {
                final int index = i;
                assertEquals(expected.get(i).asDouble(), actual[i], TOLERANCE,
                        () -> "Feature '" + UrlFeatureExtractor.FEATURE_NAMES[index]
                                + "' differs for URL: '" + url + "'");
            }
        }
    }
}
