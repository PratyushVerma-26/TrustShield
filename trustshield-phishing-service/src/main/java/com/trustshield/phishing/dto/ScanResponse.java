package com.trustshield.phishing.dto;

import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.phishing.reputation.ReputationVerdict;

import java.util.List;

/**
 * Full response for a URL scan.
 *
 * <p>Deliberately verbose. The {@link ModuleVerdict} alone is what the fusion
 * service consumes, but the dashboard and the project report both need to show
 * <em>how</em> the score was reached, so the feature attribution and the raw
 * reputation replies are returned alongside it.
 *
 * @param scanId     database id of the stored scan, for later retrieval
 * @param url        the URL as assessed
 * @param verdict    the uniform module verdict, shared with every other detector
 * @param model      which model produced the score and whether it is trained
 * @param reputation raw replies from each external source that was consulted
 * @param topFeatures the lexical features that moved the score the most
 */
public record ScanResponse(
        Long scanId,
        String url,
        ModuleVerdict verdict,
        ModelInfo model,
        List<ReputationVerdict> reputation,
        List<FeatureAttribution> topFeatures
) {

    /**
     * Model identity. {@code trained} being false is the signal that any accuracy
     * figure quoted against this response is meaningless.
     */
    public record ModelInfo(
            String version,
            String provenance,
            boolean trained,
            double probability,
            double logit
    ) {
    }

    /**
     * One feature's contribution to the decision.
     *
     * @param feature       machine name, e.g. {@code brand_impersonation}
     * @param description   plain-language meaning
     * @param standardised  the z-scored feature value that was fed to the model
     * @param logitDelta    exact contribution to the log-odds, {@code w_i * z_i}
     */
    public record FeatureAttribution(
            String feature,
            String description,
            double standardised,
            double logitDelta
    ) {
    }
}
