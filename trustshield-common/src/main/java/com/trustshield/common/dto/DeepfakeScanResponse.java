package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Forensic analysis outcome for an image or video file.
 *
 * <p>Carries the uniform {@link ModuleVerdict} along with the six inspectable
 * classical forensic signals (ELA, DQT, blockiness, noise residuals, EXIF, C2PA),
 * video temporal consistency metrics, multilingual synthetic audio indicators,
 * and internet media verification directory matches.
 *
 * @param incidentId correlation identifier
 * @param verdict uniform module verdict
 * @param metadata detected image or video properties
 * @param forensicSignals detailed measurements for the six visual signals
 * @param audioSignals audio forensic signals for synthetic voice detection
 * @param videoSignals temporal frame consistency and video container signals
 * @param directoryResult internet media verification directory result
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DeepfakeScanResponse(
        IncidentId incidentId,
        ModuleVerdict verdict,
        ImageMetadata metadata,
        ForensicSignals forensicSignals,
        AudioForensicSignals audioSignals,
        VideoTemporalSignals videoSignals,
        DirectoryLookupResult directoryResult
) {
    public DeepfakeScanResponse(IncidentId incidentId, ModuleVerdict verdict, ImageMetadata metadata, ForensicSignals forensicSignals) {
        this(incidentId, verdict, metadata, forensicSignals, AudioForensicSignals.none(), VideoTemporalSignals.none(), DirectoryLookupResult.unavailable());
    }

    public DeepfakeScanResponse {
        audioSignals = audioSignals != null ? audioSignals : AudioForensicSignals.none();
        videoSignals = videoSignals != null ? videoSignals : VideoTemporalSignals.none();
        directoryResult = directoryResult != null ? directoryResult : DirectoryLookupResult.unavailable();
    }

    public record ImageMetadata(
            String filename,
            String format,
            int width,
            int height,
            long sizeBytes,
            boolean hasExif,
            String cameraModel,
            String software,
            boolean hasC2paManifest
    ) {}

    public record ForensicSignals(
            double elaVariance,
            boolean quantisationTableAnomalous,
            String quantisationTableFingerprint,
            double spatialBlockinessScore,
            double noiseResidualVariance,
            boolean metadataInconsistent,
            boolean c2paDetected,
            boolean recompressionDetected
    ) {}

    public record AudioForensicSignals(
            boolean audioAnalyzed,
            double syntheticVoiceScore,
            boolean spectralCutoffDetected,
            double roboticPitchScore,
            double breathingPauseRatio,
            String detectedCadence
    ) {
        public static AudioForensicSignals none() {
            return new AudioForensicSignals(false, 0.0, false, 0.0, 0.0, "NONE");
        }
    }

    public record VideoTemporalSignals(
            boolean videoAnalyzed,
            int frameCount,
            double temporalJitterScore,
            double frameConsistencyScore,
            String containerSoftware
    ) {
        public static VideoTemporalSignals none() {
            return new VideoTemporalSignals(false, 0, 0.0, 1.0, null);
        }
    }

    public record DirectoryLookupResult(
            boolean consulted,
            boolean matchFound,
            String catalogSource,
            String authenticityFlag,
            String registryUrl
    ) {
        public static DirectoryLookupResult unavailable() {
            return new DirectoryLookupResult(false, false, null, null, null);
        }
    }
}
