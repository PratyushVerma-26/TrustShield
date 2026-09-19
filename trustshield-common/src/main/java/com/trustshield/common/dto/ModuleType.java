package com.trustshield.common.dto;

/**
 * Which detection module produced a result.
 *
 * <p>Used by the fusion service to weight and label evidence, and by the
 * integrity service to tag ledger entries.
 */
public enum ModuleType {

    PHISHING("Phishing & Fake Website Shield"),
    DEEPFAKE("Deepfake & Synthetic Media Detector"),
    BREACH("Personal Data Breach Monitor"),
    FAKENEWS("Misinformation Firewall"),
    FUSION("Cross-Modal Risk Fusion");

    private final String displayName;

    ModuleType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
