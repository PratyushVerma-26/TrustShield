package com.trustshield.phishing.ml;

/**
 * Output of one phishing model evaluation.
 *
 * @param probability    calibrated probability the URL is phishing, 0.0-1.0
 * @param logit          raw log-odds before the sigmoid
 * @param contributions  per-feature contribution to the logit, in
 *                       {@link UrlFeatureExtractor#FEATURE_NAMES} order.
 *                       For a linear model this is exactly {@code w_i * z_i},
 *                       which is an exact attribution rather than an
 *                       approximation, so it can be shown to users as the
 *                       reason for the verdict.
 * @param features       the standardised feature vector that was scored
 */
public record ModelPrediction(
        double probability,
        double logit,
        double[] contributions,
        double[] features
) {

    /** Probability expressed as a 0-100 risk score. */
    public int riskScore() {
        return (int) Math.round(probability * 100.0);
    }
}
