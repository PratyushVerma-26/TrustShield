package com.trustshield.deepfake.audio;

import com.trustshield.common.dto.DeepfakeScanResponse.AudioForensicSignals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure Java multilingual acoustic forensic analyzer detecting AI-generated and cloned voices.
 *
 * <p>Rather than relying on language-specific neural speech models, this analyzer exploits
 * <em>universal physical acoustic invariants</em> that neural vocoders (HiFi-GAN, MelGAN, WaveGlow)
 * and TTS systems violate across English, Hindi, Spanish, French, etc.:
 * <ol>
 *   <li><strong>Spectral Roll-off & Vocoder Cutoff:</strong> Neural vocoders synthesize speech up to
 *       strict mel-bin thresholds (typically 8 kHz or 16 kHz), lacking natural ultra-high frequency
 *       room resonance.</li>
 *   <li><strong>Robotic Prosody & Vocal Jitter:</strong> Biological vocal cords have natural cycle-to-cycle
 *       perturbations (vocal jitter $0.5\% - 1.5\%$). Synthetic voices exhibit unnaturally flat or
 *       piecewise-smoothed pitch contours.</li>
 *   <li><strong>Silence & Respiration Biophysics:</strong> Real human speech has micro-inhalations and
 *       ambient acoustic room tone ($-45$ to $-60$ dB) during pauses. Synthetic audio contains
 *       bit-exact digital zeros ($< -90$ dB) between clauses.</li>
 * </ol>
 */
@Component
public class AudioSyntheticForensicAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(AudioSyntheticForensicAnalyzer.class);

    /**
     * Analyzes raw audio bytes (WAV/RIFF format, PCM samples, or extracted audio streams).
     */
    public AudioForensicSignals analyze(byte[] audioBytes) {
        if (audioBytes == null || audioBytes.length < 500) {
            return AudioForensicSignals.none();
        }

        double[] samples = extractPcmSamples(audioBytes);
        if (samples.length < 1000) {
            return AudioForensicSignals.none();
        }

        // 1. Check for digital zero silence biophysics
        double digitalZeroRatio = measureDigitalZeroSilence(samples);

        // 2. Measure high-frequency spectral roll-off (vocoder cutoff proxy)
        boolean spectralCutoff = evaluateSpectralCutoff(samples);

        // 3. Measure robotic prosody & micro-tremor pitch variance
        double roboticPitchScore = evaluateRoboticPitchStability(samples);

        // 4. Calculate composite synthetic voice score (0.0 to 100.0)
        double syntheticScore = 0.0;
        if (spectralCutoff) {
            syntheticScore += 40.0;
        }
        syntheticScore += roboticPitchScore * 35.0;
        if (digitalZeroRatio > 0.08) {
            syntheticScore += Math.min(25.0, digitalZeroRatio * 150.0);
        }

        syntheticScore = Math.min(96.0, Math.max(0.0, syntheticScore));

        // 5. Determine detected cadence label
        String detectedCadence = "NATURAL_HUMAN";
        if (syntheticScore >= 65.0) {
            if (spectralCutoff && roboticPitchScore > 0.6) {
                detectedCadence = "NEURAL_VOCODER_SYNTHETIC";
            } else if (digitalZeroRatio > 0.12) {
                detectedCadence = "DIGITAL_ZERO_SILENCE";
            } else {
                detectedCadence = "SYNTHETIC_FLAT_PROSODY";
            }
        }

        return new AudioForensicSignals(
                true,
                round2(syntheticScore),
                spectralCutoff,
                round2(roboticPitchScore),
                round2(digitalZeroRatio),
                detectedCadence
        );
    }

    /**
     * Extracts normalized PCM samples in [-1.0, 1.0] from RIFF WAV or raw 16-bit PCM.
     */
    private double[] extractPcmSamples(byte[] bytes) {
        int dataOffset = 0;
        int dataLength = bytes.length;

        // Check for RIFF WAVE header
        if (bytes.length > 44 && bytes[0] == 'R' && bytes[1] == 'I' && bytes[2] == 'F' && bytes[3] == 'F') {
            // Find 'data' chunk
            for (int i = 12; i < bytes.length - 8; i++) {
                if (bytes[i] == 'd' && bytes[i + 1] == 'a' && bytes[i + 2] == 't' && bytes[i + 3] == 'a') {
                    dataOffset = i + 8;
                    int chunkSize = ((bytes[i + 4] & 0xFF)) |
                                    ((bytes[i + 5] & 0xFF) << 8) |
                                    ((bytes[i + 6] & 0xFF) << 16) |
                                    ((bytes[i + 7] & 0xFF) << 24);
                    dataLength = Math.min(chunkSize, bytes.length - dataOffset);
                    break;
                }
            }
        }

        int sampleCount = dataLength / 2;
        if (sampleCount <= 0) return new double[0];

        // Limit to first 48,000 samples (~3 seconds at 16kHz) for sub-millisecond execution
        int limit = Math.min(sampleCount, 48000);
        double[] samples = new double[limit];

        ByteBuffer buffer = ByteBuffer.wrap(bytes, dataOffset, limit * 2).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < limit; i++) {
            short s = buffer.getShort();
            samples[i] = s / 32768.0;
        }

        return samples;
    }

    /**
     * Detects artificial digital zero floors during pause intervals.
     * Human speech in real acoustic environments retains room tone noise floor (~ -45 dB to -60 dB).
     */
    private double measureDigitalZeroSilence(double[] samples) {
        int zeroCount = 0;
        for (double s : samples) {
            if (Math.abs(s) < 0.00005) { // Exact or near-exact digital zero (< -86 dB)
                zeroCount++;
            }
        }
        return (double) zeroCount / samples.length;
    }

    /**
     * Evaluates high-frequency spectral energy roll-off.
     * Neural vocoders suffer from sharp high-frequency brick-wall attenuation above their mel-frequency limit.
     */
    private boolean evaluateSpectralCutoff(double[] samples) {
        // High-pass difference filter: y[n] = x[n] - x[n-1] (isolates highest frequency band)
        double highEnergy = 0.0;
        double totalEnergy = 0.0;

        for (int i = 1; i < samples.length; i++) {
            double diff = samples[i] - samples[i - 1];
            highEnergy += diff * diff;
            totalEnergy += samples[i] * samples[i];
        }

        if (totalEnergy < 0.001) {
            return false; // Silent audio
        }

        double highRatio = highEnergy / totalEnergy;
        // In natural human speech with sibilants, highRatio is typically > 0.25.
        // In low-pass filtered or 8kHz neural vocoder outputs, highRatio is abnormally suppressed (< 0.06).
        return highRatio < 0.055;
    }

    /**
     * Measures robotic pitch micro-tremor unnaturalness.
     * Natural human speech exhibits pitch jitter ($0.5\% - 1.5\%$).
     * AI speech generators exhibit rigid harmonic periodicity with near-zero vocal jitter.
     */
    private double evaluateRoboticPitchStability(double[] samples) {
        int frameSize = 320; // 20ms at 16kHz
        int step = 160;      // 10ms hop
        List<Double> zeroCrossingRates = new ArrayList<>();

        for (int start = 0; start + frameSize <= samples.length; start += step) {
            int zc = 0;
            for (int i = start + 1; i < start + frameSize; i++) {
                if ((samples[i] >= 0 && samples[i - 1] < 0) || (samples[i] < 0 && samples[i - 1] >= 0)) {
                    zc++;
                }
            }
            zeroCrossingRates.add((double) zc / frameSize);
        }

        if (zeroCrossingRates.size() < 10) {
            return 0.0;
        }

        // Calculate variance of zero crossing rates across voiced frames
        double mean = 0.0;
        for (double r : zeroCrossingRates) mean += r;
        mean /= zeroCrossingRates.size();

        double variance = 0.0;
        for (double r : zeroCrossingRates) {
            variance += Math.pow(r - mean, 2);
        }
        variance /= zeroCrossingRates.size();

        // Abnormally low variance in zero-crossing rate indicates robotic monotonic speech
        if (variance < 0.0015 && mean > 0.04) {
            return Math.min(1.0, 0.6 + (0.0015 - variance) * 250.0);
        }

        return Math.max(0.0, Math.min(0.5, 0.005 / (variance + 0.005)));
    }

    private static double round2(double v) {
        return Math.round(v * 100.0) / 100.0;
    }
}
