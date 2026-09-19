package com.trustshield.phishing.ml;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Logistic regression classifier for phishing URLs.
 *
 * <p>Weights are loaded from a JSON file produced by
 * {@code scripts/train_phishing_model.py} rather than hard-coded, so the model
 * can be retrained without touching Java. The file also carries a
 * {@code provenance} field; if it reports {@code HEURISTIC_BOOTSTRAP} the model
 * has not been trained on real data and this class logs a prominent warning at
 * startup. That warning exists so nobody can accidentally report accuracy
 * figures for an untrained model.
 *
 * <p>Logistic regression is chosen over a gradient-boosted or neural model for
 * three reasons: inference is a single dot product over local state, with no
 * network round-trip in the hot path; the per-feature contribution
 * {@code w_i * z_i} is an exact attribution, giving genuine explainability
 * rather than a post-hoc approximation; and with 26 features and a modest
 * training set it is far less prone to overfitting than a high-capacity
 * alternative.
 *
 * <p><strong>A rare binary feature dominates this model, by construction.</strong>
 * Standardisation divides by the feature's standard deviation, so an indicator
 * with mean {@code 0.03} has {@code z = 5.7} whenever it fires. With a
 * coefficient of {@code 0.9} that is {@code +5.1} of logit from one boolean,
 * enough to put any URL in DANGEROUS on its own regardless of the other 25
 * features. That is arithmetically correct behaviour for logistic regression and
 * it is still a liability while the weights are hand-chosen priors, because it
 * means the verdict inherits the precision of a single unmeasured signal.
 * Observed directly: a legitimate bank host scored 90 because
 * {@code brand_impersonation} misfired. The signal was made more precise rather
 * than the weight quietly reduced, since reducing it would hide the property
 * instead of addressing it. Retraining on labelled data is the actual fix.
 */
@Component
public class PhishingModel {

    private static final Logger log = LoggerFactory.getLogger(PhishingModel.class);

    private final ResourceLoader resourceLoader;
    private final ObjectMapper objectMapper;

    @Value("${trustshield.phishing.model-path:classpath:models/phishing_model.json}")
    private String modelPath;

    private double[] mean;
    private double[] scale;
    private double[] coefficients;
    private double intercept;
    private String provenance = "UNKNOWN";
    private String modelVersion = "unknown";
    private boolean trained;

    public PhishingModel(ResourceLoader resourceLoader, ObjectMapper objectMapper) {
        this.resourceLoader = resourceLoader;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    void load() {
        Resource resource = resourceLoader.getResource(modelPath);
        if (!resource.exists()) {
            throw new IllegalStateException(
                    "Phishing model not found at " + modelPath
                            + ". The service cannot classify without it. Run "
                            + "scripts/train_phishing_model.py or restore the bundled bootstrap file.");
        }

        try (InputStream in = resource.getInputStream()) {
            JsonNode root = objectMapper.readTree(in);

            this.modelVersion = root.path("version").asText("unknown");
            this.provenance = root.path("provenance").asText("UNKNOWN");
            this.intercept = root.path("intercept").asDouble(0.0);
            this.mean = readVector(root, "mean");
            this.scale = readVector(root, "scale");
            this.coefficients = readVector(root, "coefficients");

            validateFeatureOrder(root);
            validateDimensions();
            guardAgainstZeroScale();

            this.trained = "TRAINED".equalsIgnoreCase(provenance);

            if (trained) {
                log.info("Phishing model loaded. version={} provenance={} features={}",
                        modelVersion, provenance, coefficients.length);
            } else {
                log.warn("""
                        =====================================================================
                        PHISHING MODEL IS NOT TRAINED (provenance={}).
                        The bundled weights are a hand-initialised bootstrap intended only to
                        make the service runnable before training. Do NOT report accuracy
                        figures from this model. Train a real one with:
                            python scripts/train_phishing_model.py --data data/urls.csv
                        =====================================================================""",
                        provenance);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read phishing model from " + modelPath, e);
        }
    }

    /**
     * Scores a URL.
     *
     * @param rawUrl URL as submitted by the user
     * @return prediction including per-feature attribution
     */
    public ModelPrediction predict(String rawUrl) {
        double[] raw = UrlFeatureExtractor.extract(rawUrl);
        double[] standardised = new double[raw.length];
        double[] contributions = new double[raw.length];

        double logit = intercept;
        for (int i = 0; i < raw.length; i++) {
            standardised[i] = (raw[i] - mean[i]) / scale[i];
            contributions[i] = coefficients[i] * standardised[i];
            logit += contributions[i];
        }

        return new ModelPrediction(sigmoid(logit), logit, contributions, standardised);
    }

    /** True when the loaded weights came from actual training. */
    public boolean isTrained() {
        return trained;
    }

    public String getProvenance() {
        return provenance;
    }

    public String getModelVersion() {
        return modelVersion;
    }

    private static double sigmoid(double z) {
        // Branch on sign to avoid overflow of exp() for large negative z.
        if (z >= 0) {
            return 1.0 / (1.0 + Math.exp(-z));
        }
        double ez = Math.exp(z);
        return ez / (1.0 + ez);
    }

    private double[] readVector(JsonNode root, String field) {
        JsonNode node = root.path(field);
        if (!node.isArray()) {
            throw new IllegalStateException(
                    "Model file field '" + field + "' is missing or not an array");
        }
        double[] out = new double[node.size()];
        for (int i = 0; i < node.size(); i++) {
            out[i] = node.get(i).asDouble();
        }
        return out;
    }

    /**
     * Confirms the model was trained on the same features, in the same order,
     * that this build extracts. Silent feature drift between the training script
     * and the Java extractor would apply coefficients to the wrong columns and
     * produce confidently wrong verdicts, so this is a hard failure.
     */
    private void validateFeatureOrder(JsonNode root) {
        JsonNode names = root.path("featureNames");
        if (!names.isArray()) {
            log.warn("Model file has no featureNames array; cannot verify feature order. "
                    + "Proceeding on the assumption it matches UrlFeatureExtractor.");
            return;
        }
        String[] expected = UrlFeatureExtractor.FEATURE_NAMES;
        if (names.size() != expected.length) {
            throw new IllegalStateException(
                    "Model expects " + names.size() + " features but UrlFeatureExtractor produces "
                            + expected.length + ". Retrain the model against the current extractor.");
        }
        for (int i = 0; i < expected.length; i++) {
            String actual = names.get(i).asText();
            if (!expected[i].equals(actual)) {
                throw new IllegalStateException(
                        "Feature order mismatch at index " + i + ": model has '" + actual
                                + "' but extractor produces '" + expected[i]
                                + "'. Retrain the model against the current extractor.");
            }
        }
    }

    private void validateDimensions() {
        int n = UrlFeatureExtractor.FEATURE_COUNT;
        if (mean.length != n || scale.length != n || coefficients.length != n) {
            throw new IllegalStateException(String.format(
                    "Model dimension mismatch: expected %d features but got mean=%d scale=%d coefficients=%d",
                    n, mean.length, scale.length, coefficients.length));
        }
    }

    /**
     * A zero in the scale vector would divide by zero and yield NaN, silently
     * poisoning every downstream score. Happens when a feature is constant across
     * the training set. Substituting 1.0 makes that feature contribute only
     * through its (also near-zero) coefficient.
     */
    private void guardAgainstZeroScale() {
        for (int i = 0; i < scale.length; i++) {
            if (scale[i] == 0.0 || Double.isNaN(scale[i])) {
                log.warn("Feature '{}' has zero variance in the training set; "
                                + "substituting scale=1.0 to avoid NaN scores.",
                        UrlFeatureExtractor.FEATURE_NAMES[i]);
                scale[i] = 1.0;
            }
        }
    }

    @Override
    public String toString() {
        return "PhishingModel{version=" + modelVersion
                + ", provenance=" + provenance
                + ", features=" + (coefficients == null ? 0 : coefficients.length)
                + ", intercept=" + intercept
                + ", coefficients=" + Arrays.toString(coefficients) + "}";
    }
}
