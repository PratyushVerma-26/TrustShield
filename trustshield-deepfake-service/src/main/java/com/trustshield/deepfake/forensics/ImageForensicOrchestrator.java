package com.trustshield.deepfake.forensics;

import com.trustshield.common.dto.DeepfakeScanResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleType;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import com.trustshield.common.dto.ThreatSignal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Coordinates execution of the six inspectable offline forensic signal analyzers.
 *
 * <p>Enforces the system invariants:
 * <ol>
 *   <li><strong>Recompression Handling:</strong> If recompression destroyed forensic traces,
 *       emit {@link ThreatLevel#UNKNOWN} (score 0, degraded=true).</li>
 *   <li><strong>Inspectable Signals:</strong> Every point of risk score is backed by a discrete {@link ThreatSignal}.</li>
 *   <li><strong>Generative AI Caveat:</strong> Clearly state in verdicts that classical forensics does not
 *       reliably detect modern generative outputs lacking compression artifacts.</li>
 * </ol>
 */
@Component
public class ImageForensicOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ImageForensicOrchestrator.class);

    private final ElaAnalyzer elaAnalyzer;
    private final JpegQuantizationAnalyzer dqtAnalyzer;
    private final SpatialBlockinessAnalyzer blockinessAnalyzer;
    private final NoiseResidualAnalyzer noiseAnalyzer;
    private final ExifProvenanceAnalyzer exifAnalyzer;
    private final C2paManifestDetector c2paDetector;
    private final RecompressionDetector recompressionDetector;
    private final com.trustshield.deepfake.video.VideoContainerParser videoParser;
    private final com.trustshield.deepfake.video.VideoTemporalAnalyzer temporalAnalyzer;
    private final com.trustshield.deepfake.audio.AudioSyntheticForensicAnalyzer audioAnalyzer;
    private final com.trustshield.deepfake.directory.InternetMediaDirectoryClient directoryClient;

    @Value("${trustshield.deepfake.forensics.ela-quality:0.90}")
    private float elaQuality;

    @Value("${trustshield.deepfake.forensics.ela-variance-threshold:120.0}")
    private double elaVarianceThreshold;

    @Value("${trustshield.deepfake.forensics.blockiness-periodicity-threshold:0.70}")
    private double blockinessThreshold;

    @Value("${trustshield.deepfake.forensics.noise-residual-variance-threshold:85.0}")
    private double noiseVarianceThreshold;

    @Value("${trustshield.deepfake.forensics.noise-hyper-smooth-threshold:1.5}")
    private double noiseHyperSmoothThreshold;

    public ImageForensicOrchestrator(
            ElaAnalyzer elaAnalyzer,
            JpegQuantizationAnalyzer dqtAnalyzer,
            SpatialBlockinessAnalyzer blockinessAnalyzer,
            NoiseResidualAnalyzer noiseAnalyzer,
            ExifProvenanceAnalyzer exifAnalyzer,
            C2paManifestDetector c2paDetector,
            RecompressionDetector recompressionDetector
    ) {
        this(elaAnalyzer, dqtAnalyzer, blockinessAnalyzer, noiseAnalyzer, exifAnalyzer, c2paDetector, recompressionDetector,
             new com.trustshield.deepfake.video.VideoContainerParser(),
             new com.trustshield.deepfake.video.VideoTemporalAnalyzer(noiseAnalyzer, blockinessAnalyzer),
             new com.trustshield.deepfake.audio.AudioSyntheticForensicAnalyzer(),
             new com.trustshield.deepfake.directory.InternetMediaDirectoryClient());
    }

    @Autowired
    public ImageForensicOrchestrator(
            ElaAnalyzer elaAnalyzer,
            JpegQuantizationAnalyzer dqtAnalyzer,
            SpatialBlockinessAnalyzer blockinessAnalyzer,
            NoiseResidualAnalyzer noiseAnalyzer,
            ExifProvenanceAnalyzer exifAnalyzer,
            C2paManifestDetector c2paDetector,
            RecompressionDetector recompressionDetector,
            com.trustshield.deepfake.video.VideoContainerParser videoParser,
            com.trustshield.deepfake.video.VideoTemporalAnalyzer temporalAnalyzer,
            com.trustshield.deepfake.audio.AudioSyntheticForensicAnalyzer audioAnalyzer,
            com.trustshield.deepfake.directory.InternetMediaDirectoryClient directoryClient
    ) {
        this.elaAnalyzer = elaAnalyzer;
        this.dqtAnalyzer = dqtAnalyzer;
        this.blockinessAnalyzer = blockinessAnalyzer;
        this.noiseAnalyzer = noiseAnalyzer;
        this.exifAnalyzer = exifAnalyzer;
        this.c2paDetector = c2paDetector;
        this.recompressionDetector = recompressionDetector;
        this.videoParser = videoParser;
        this.temporalAnalyzer = temporalAnalyzer;
        this.audioAnalyzer = audioAnalyzer;
        this.directoryClient = directoryClient;
    }

    /**
     * Executes the six forensic analyzers and constructs a complete DeepfakeScanResponse.
     */
    public DeepfakeScanResponse orchestrate(
            IncidentId incidentId,
            byte[] rawBytes,
            String filename,
            String declaredMimeType,
            String context
    ) {
        long startNanos = System.nanoTime();

        if (rawBytes == null || rawBytes.length == 0) {
            ModuleVerdict verdict = ModuleVerdict.inconclusive(
                    ModuleType.DEEPFAKE,
                    "EMPTY_PAYLOAD",
                    "No image data provided for forensic analysis",
                    List.of(ThreatSignal.triggered("EMPTY_PAYLOAD", "Payload byte array was empty", 0, "INPUT_VALIDATOR")),
                    0
            );
            return new DeepfakeScanResponse(
                    incidentId,
                    verdict,
                    new DeepfakeScanResponse.ImageMetadata(filename, "UNKNOWN", 0, 0, 0, false, null, null, false),
                    new DeepfakeScanResponse.ForensicSignals(0.0, false, "NONE", 0.0, 0.0, false, false, false)
            );
        }

        BufferedImage image;
        try {
            image = ImageIO.read(new ByteArrayInputStream(rawBytes));
        } catch (Exception e) {
            long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);
            ModuleVerdict verdict = ModuleVerdict.inconclusive(
                    ModuleType.DEEPFAKE,
                    "IMAGE_DECODE_FAILED",
                    "Image decoding failed: " + e.getMessage(),
                    List.of(ThreatSignal.triggered("DECODE_ERROR", e.getMessage(), 0, "IMAGE_IO")),
                    latencyMs
            );
            return new DeepfakeScanResponse(
                    incidentId,
                    verdict,
                    new DeepfakeScanResponse.ImageMetadata(filename, "CORRUPT", 0, 0, rawBytes.length, false, null, null, false),
                    new DeepfakeScanResponse.ForensicSignals(0.0, false, "NONE", 0.0, 0.0, false, false, false)
            );
        }

        if (image == null) {
            // Check if input is a video container (MP4, WebM, QuickTime, AVI)
            var containerInfo = videoParser.parse(rawBytes);
            if (containerInfo.isVideoContainer()) {
                return orchestrateVideo(incidentId, rawBytes, filename, declaredMimeType, context, containerInfo, startNanos);
            }

            // Check if input is pure audio (WAV/RIFF or audio MIME type)
            if (isAudioPayload(rawBytes, declaredMimeType, filename)) {
                return orchestrateAudio(incidentId, rawBytes, filename, declaredMimeType, context, startNanos);
            }

            long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);
            ModuleVerdict verdict = ModuleVerdict.inconclusive(
                    ModuleType.DEEPFAKE,
                    "UNRECOGNIZED_FORMAT",
                    "Format not supported by media readers",
                    List.of(ThreatSignal.triggered("UNRECOGNIZED_FORMAT", "Format could not be parsed by registered ImageIO or media readers", 0, "MEDIA_IO")),
                    latencyMs
            );
            return new DeepfakeScanResponse(
                    incidentId,
                    verdict,
                    new DeepfakeScanResponse.ImageMetadata(filename, "UNSUPPORTED", 0, 0, rawBytes.length, false, null, null, false),
                    new DeepfakeScanResponse.ForensicSignals(0.0, false, "NONE", 0.0, 0.0, false, false, false)
            );
        }

        int width = image.getWidth();
        int height = image.getHeight();
        String format = detectFormat(rawBytes, filename);

        // 1. Run all 6 analyzers
        ElaAnalyzer.ElaResult ela = elaAnalyzer.analyze(image, elaQuality, elaVarianceThreshold);
        JpegQuantizationAnalyzer.DqtResult dqt = dqtAnalyzer.analyze(rawBytes);
        SpatialBlockinessAnalyzer.BlockinessResult blockiness = blockinessAnalyzer.analyze(image, blockinessThreshold);
        NoiseResidualAnalyzer.NoiseResidualResult noise = noiseAnalyzer.analyze(image, noiseVarianceThreshold, noiseHyperSmoothThreshold);
        ExifProvenanceAnalyzer.ExifResult exif = exifAnalyzer.analyze(rawBytes);
        C2paManifestDetector.C2paResult c2pa = c2paDetector.detect(rawBytes);

        // 2. Check for recompression failure case
        RecompressionDetector.RecompressionResult recompression = recompressionDetector.evaluate(
                image, rawBytes.length, exif.hasExif(), blockiness.periodicityScore(), noise.variance(), context
        );

        // 3. Query Internet Media Directory
        var directoryResult = directoryClient.lookup(rawBytes, c2pa.detected());

        long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);

        List<ThreatSignal> signals = new ArrayList<>();

        DeepfakeScanResponse.ImageMetadata metadata = new DeepfakeScanResponse.ImageMetadata(
                filename,
                format,
                width,
                height,
                rawBytes.length,
                exif.hasExif(),
                exif.cameraModel(),
                exif.software(),
                c2pa.detected()
        );

        DeepfakeScanResponse.ForensicSignals forensicSignals = new DeepfakeScanResponse.ForensicSignals(
                ela.variance(),
                dqt.anomalous(),
                dqt.fingerprint(),
                blockiness.periodicityScore(),
                noise.variance(),
                exif.metadataInconsistent(),
                c2pa.detected(),
                recompression.recompressed()
        );

        // Invariant: Recompressed image cannot produce conclusive verdict
        if (recompression.recompressed()) {
            signals.add(ThreatSignal.triggered(
                    "FORENSIC_TRACES_DESTROYED",
                    recompression.detail(),
                    0,
                    "RECOMPRESSION_DETECTOR"
            ));

            String explanation = "Forensic traces destroyed by lossy recompression or downscaling; authentic provenance cannot be determined. "
                    + "Inspecting the original uncompressed document file is recommended.";

            ModuleVerdict verdict = ModuleVerdict.inconclusive(
                    ModuleType.DEEPFAKE,
                    "IMAGE_RECOMPRESSED",
                    explanation,
                    signals,
                    latencyMs
            );

            return new DeepfakeScanResponse(
                    incidentId, verdict, metadata, forensicSignals,
                    DeepfakeScanResponse.AudioForensicSignals.none(),
                    DeepfakeScanResponse.VideoTemporalSignals.none(),
                    directoryResult
            );
        }

        // Calculate score from forensic evidence
        int score = 0;

        if (directoryResult.matchFound() && !"MANIFEST_VERIFIED_AUTHENTIC".equals(directoryResult.authenticityFlag())) {
            score = Math.max(score, 95);
            signals.add(ThreatSignal.triggered("DIRECTORY_CONFIRMED_MANIPULATION", "Corroborated in " + directoryResult.catalogSource() + " as synthetic media: " + directoryResult.registryUrl(), 95, "MEDIA_DIRECTORY"));
        }

        if (dqt.anomalous()) {
            score += 35;
            signals.add(ThreatSignal.triggered("DQT_ANOMALY", dqt.detail(), 35, "JPEG_DQT_ANALYZER"));
        } else {
            signals.add(ThreatSignal.passed("DQT_VERIFIED", dqt.detail(), "JPEG_DQT_ANALYZER"));
        }

        if (ela.anomalous()) {
            score += 30;
            signals.add(ThreatSignal.triggered("ELA_DISCREPANCY", ela.detail(), 30, "ELA_ANALYZER"));
        } else {
            signals.add(ThreatSignal.passed("ELA_UNIFORM", ela.detail(), "ELA_ANALYZER"));
        }

        if (noise.hyperSmooth()) {
            score += 25;
            signals.add(ThreatSignal.triggered("NOISE_HYPER_SMOOTH", noise.detail(), 25, "NOISE_RESIDUAL_ANALYZER"));
        } else if (noise.anomalous()) {
            score += 20;
            signals.add(ThreatSignal.triggered("NOISE_INCONSISTENCY", noise.detail(), 20, "NOISE_RESIDUAL_ANALYZER"));
        } else {
            signals.add(ThreatSignal.passed("NOISE_CONSISTENT", noise.detail(), "NOISE_RESIDUAL_ANALYZER"));
        }

        if (exif.metadataInconsistent()) {
            score += 20;
            signals.add(ThreatSignal.triggered("METADATA_INCONSISTENT", exif.detail(), 20, "EXIF_PROVENANCE_ANALYZER"));
        } else if (exif.hasExif()) {
            signals.add(ThreatSignal.passed("EXIF_PROVENANCE", exif.detail(), "EXIF_PROVENANCE_ANALYZER"));
        }

        if (blockiness.anomalous()) {
            score += 15;
            signals.add(ThreatSignal.triggered("BLOCKINESS_ELEVATED", blockiness.detail(), 15, "SPATIAL_BLOCKINESS_ANALYZER"));
        } else {
            signals.add(ThreatSignal.passed("BLOCKINESS_NORMAL", blockiness.detail(), "SPATIAL_BLOCKINESS_ANALYZER"));
        }

        if (c2pa.detected()) {
            signals.add(ThreatSignal.passed("C2PA_MANIFEST", c2pa.detail(), "C2PA_DETECTOR"));
        }

        score = Math.min(100, score);
        ThreatLevel level = ThreatLevel.fromScore(score);

        String verdictCode;
        String explanation;

        if (directoryResult.matchFound() && !"MANIFEST_VERIFIED_AUTHENTIC".equals(directoryResult.authenticityFlag())) {
            verdictCode = "DIRECTORY_CONFIRMED_SYNTHETIC";
            explanation = String.format("Media verified as synthetic in %s. Visual forensic score: %d.", directoryResult.catalogSource(), score);
        } else if (level == ThreatLevel.DANGEROUS) {
            verdictCode = "MANIPULATION_DETECTED";
            explanation = String.format("Multiple classical forensic anomalies identified (score: %d). Physical compression and noise statistics indicate image manipulation or synthetic generation.", score);
        } else if (level == ThreatLevel.SUSPICIOUS) {
            verdictCode = "FORENSIC_ANOMALIES_PRESENT";
            explanation = String.format("Forensic anomalies detected (score: %d). Inconsistencies present in quantization or high-frequency residual distribution.", score);
        } else {
            verdictCode = "NO_MANIPULATION_TRACES";
            explanation = String.format("No classical compression or ELA anomalies detected (score: %d). Caveat: classical forensics inspects physical compression artifacts and does not reliably detect pure generative AI models that reproduce uniform statistics.", score);
        }

        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.DEEPFAKE,
                score,
                verdictCode,
                explanation,
                signals,
                latencyMs
        );

        return new DeepfakeScanResponse(
                incidentId, verdict, metadata, forensicSignals,
                DeepfakeScanResponse.AudioForensicSignals.none(),
                DeepfakeScanResponse.VideoTemporalSignals.none(),
                directoryResult
        );
    }

    private DeepfakeScanResponse orchestrateVideo(
            IncidentId incidentId,
            byte[] rawBytes,
            String filename,
            String declaredMimeType,
            String context,
            com.trustshield.deepfake.video.VideoContainerParser.VideoContainerInfo containerInfo,
            long startNanos
    ) {
        long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);
        List<ThreatSignal> signals = new ArrayList<>();

        var audioSignals = com.trustshield.common.dto.DeepfakeScanResponse.AudioForensicSignals.none();
        if (containerInfo.hasAudioTrack() || rawBytes.length > 2048) {
            audioSignals = audioAnalyzer.analyze(rawBytes);
        }

        var videoSignals = temporalAnalyzer.analyzeVideoBytes(rawBytes, containerInfo.editingSoftware());
        var directoryResult = directoryClient.lookup(rawBytes, false);

        int score = 0;

        if (directoryResult.matchFound() && !"MANIFEST_VERIFIED_AUTHENTIC".equals(directoryResult.authenticityFlag())) {
            score = 95;
            signals.add(ThreatSignal.triggered(
                    "DIRECTORY_CONFIRMED_SYNTHETIC",
                    "Matched in " + directoryResult.catalogSource() + " (" + directoryResult.authenticityFlag() + ")",
                    95,
                    "MEDIA_DIRECTORY"
            ));
        }

        if (audioSignals.audioAnalyzed()) {
            if (audioSignals.syntheticVoiceScore() >= 60.0) {
                int audioContrib = (int) Math.round(audioSignals.syntheticVoiceScore() * 0.85);
                score = Math.max(score, audioContrib);
                signals.add(ThreatSignal.triggered(
                        "SYNTHETIC_VOICE_DETECTED",
                        "Multi-language acoustic analysis indicates synthetic/cloned speech (" + audioSignals.detectedCadence() + ", robotic pitch: " + audioSignals.roboticPitchScore() + ")",
                        audioContrib,
                        "AUDIO_ACOUSTIC_ANALYZER"
                ));
            } else {
                signals.add(ThreatSignal.passed(
                        "AUDIO_PROSODY_ORGANIC",
                        "Acoustic pitch and room resonance consistent with organic human speech",
                        "AUDIO_ACOUSTIC_ANALYZER"
                ));
            }
        }

        if (videoSignals.videoAnalyzed()) {
            if (videoSignals.temporalJitterScore() >= 0.55) {
                int jitterContrib = (int) Math.round(videoSignals.temporalJitterScore() * 75);
                score = Math.max(score, jitterContrib);
                signals.add(ThreatSignal.triggered(
                        "TEMPORAL_INCOHERENCE",
                        "Inter-frame noise disparity and facial boundary jitter detected (jitter: " + videoSignals.temporalJitterScore() + ")",
                        jitterContrib,
                        "VIDEO_TEMPORAL_ANALYZER"
                ));
            } else {
                signals.add(ThreatSignal.passed(
                        "TEMPORAL_COHERENT",
                        "Inter-frame noise residual envelope is temporally consistent",
                        "VIDEO_TEMPORAL_ANALYZER"
                ));
            }
        }

        if (containerInfo.editingSoftware() != null) {
            score = Math.max(score, 40);
            signals.add(ThreatSignal.triggered(
                    "EDITING_SOFTWARE_METADATA",
                    "Video container headers identify editing/AI toolchain: " + containerInfo.editingSoftware(),
                    40,
                    "VIDEO_CONTAINER_PARSER"
            ));
        }

        score = Math.min(100, score);
        ThreatLevel level = ThreatLevel.fromScore(score);

        String verdictCode = level == ThreatLevel.DANGEROUS ? "SYNTHETIC_VIDEO_DETECTED" :
                (level == ThreatLevel.SUSPICIOUS ? "VIDEO_ANOMALIES_PRESENT" : "NO_MANIPULATION_TRACES");

        String explanation = String.format(
                "Multimodal video evaluation complete (format: %s, audio: %s, temporal jitter: %.2f). %s",
                containerInfo.format(),
                audioSignals.audioAnalyzed() ? audioSignals.detectedCadence() : "NO_AUDIO",
                videoSignals.temporalJitterScore(),
                level == ThreatLevel.DANGEROUS ? "High confidence of video manipulation or synthetic voice generation." :
                        (level == ThreatLevel.SUSPICIOUS ? "Anomalies detected in audio-visual consistency." : "No significant synthetic video/audio artifacts detected.")
        );

        ModuleVerdict verdict = ModuleVerdict.of(
                ModuleType.DEEPFAKE,
                score,
                verdictCode,
                explanation,
                signals,
                latencyMs
        );

        DeepfakeScanResponse.ImageMetadata metadata = new DeepfakeScanResponse.ImageMetadata(
                filename, containerInfo.format(), 1920, 1080, rawBytes.length, false, null, containerInfo.editingSoftware(), false
        );

        DeepfakeScanResponse.ForensicSignals forensicSignals = new DeepfakeScanResponse.ForensicSignals(
                0.0, false, "VIDEO_CONTAINER", videoSignals.temporalJitterScore(), 0.0, containerInfo.editingSoftware() != null, false, false
        );

        return new DeepfakeScanResponse(
                incidentId,
                verdict,
                metadata,
                forensicSignals,
                audioSignals,
                videoSignals,
                directoryResult
        );
    }

    private DeepfakeScanResponse orchestrateAudio(
            IncidentId incidentId,
            byte[] rawBytes,
            String filename,
            String declaredMimeType,
            String context,
            long startNanos
    ) {
        long latencyMs = Math.round((System.nanoTime() - startNanos) / 1_000_000.0);
        List<ThreatSignal> signals = new ArrayList<>();

        var audioSignals = audioAnalyzer.analyze(rawBytes);
        var directoryResult = directoryClient.lookup(rawBytes, false);

        int score = 0;

        if (directoryResult.matchFound()) {
            score = 95;
            signals.add(ThreatSignal.triggered("DIRECTORY_CONFIRMED_SYNTHETIC", "Matched in " + directoryResult.catalogSource(), 95, "MEDIA_DIRECTORY"));
        }

        if (audioSignals.syntheticVoiceScore() >= 60.0) {
            int audioContrib = (int) Math.round(audioSignals.syntheticVoiceScore() * 0.9);
            score = Math.max(score, audioContrib);
            signals.add(ThreatSignal.triggered(
                    "SYNTHETIC_VOICE_DETECTED",
                    "Acoustic analysis indicates cloned/synthetic voice (" + audioSignals.detectedCadence() + ", score: " + audioSignals.syntheticVoiceScore() + ")",
                    audioContrib,
                    "AUDIO_ACOUSTIC_ANALYZER"
            ));
        } else {
            signals.add(ThreatSignal.passed("AUDIO_ORGANIC", "Acoustic micro-tremor and spectral roll-off within human biophysical parameters", "AUDIO_ACOUSTIC_ANALYZER"));
        }

        score = Math.min(100, score);
        ThreatLevel level = ThreatLevel.fromScore(score);

        String verdictCode = level == ThreatLevel.DANGEROUS ? "SYNTHETIC_AUDIO_DETECTED" :
                (level == ThreatLevel.SUSPICIOUS ? "AUDIO_ANOMALIES_PRESENT" : "ORGANIC_AUDIO");

        String explanation = String.format("Acoustic voice analysis complete (%s, score: %d). %s",
                audioSignals.detectedCadence(), score,
                level == ThreatLevel.DANGEROUS ? "High confidence of synthetic voice cloning / vocoder synthesis." : "No synthetic speech anomalies detected.");

        ModuleVerdict verdict = ModuleVerdict.of(ModuleType.DEEPFAKE, score, verdictCode, explanation, signals, latencyMs);

        DeepfakeScanResponse.ImageMetadata metadata = new DeepfakeScanResponse.ImageMetadata(
                filename, "AUDIO_WAV", 0, 0, rawBytes.length, false, null, null, false
        );
        DeepfakeScanResponse.ForensicSignals forensicSignals = new DeepfakeScanResponse.ForensicSignals(
                0.0, false, "AUDIO_STREAM", 0.0, 0.0, false, false, false
        );

        return new DeepfakeScanResponse(
                incidentId, verdict, metadata, forensicSignals, audioSignals, DeepfakeScanResponse.VideoTemporalSignals.none(), directoryResult
        );
    }

    private boolean isAudioPayload(byte[] bytes, String mimeType, String filename) {
        if (mimeType != null && mimeType.toLowerCase().startsWith("audio/")) {
            return true;
        }
        if (filename != null && (filename.toLowerCase().endsWith(".wav") || filename.toLowerCase().endsWith(".mp3") || filename.toLowerCase().endsWith(".m4a"))) {
            return true;
        }
        return bytes.length > 12 && bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F' &&
               bytes[8] == 'W' && bytes[9] == 'A' && bytes[10] == 'V' && bytes[11] == 'E';
    }

    private String detectFormat(byte[] bytes, String filename) {
        if (bytes.length >= 2 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8) {
            return "JPEG";
        }
        if (bytes.length >= 8 && (bytes[0] & 0xFF) == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G') {
            return "PNG";
        }
        if (filename != null && filename.contains(".")) {
            return filename.substring(filename.lastIndexOf('.') + 1).toUpperCase();
        }
        return "UNKNOWN";
    }
}
