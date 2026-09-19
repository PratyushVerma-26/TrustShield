package com.trustshield.deepfake.audio;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.assertj.core.api.Assertions.assertThat;

class AudioSyntheticForensicAnalyzerTest {

    private final AudioSyntheticForensicAnalyzer analyzer = new AudioSyntheticForensicAnalyzer();

    @Test
    @DisplayName("returns none() for null or truncated audio bytes")
    void handlesEmptyAudio() {
        var result = analyzer.analyze(new byte[10]);
        assertThat(result.audioAnalyzed()).isFalse();
    }

    @Test
    @DisplayName("evaluates organic speech with natural pitch micro-tremor and ambient tone")
    void evaluatesOrganicAudio() {
        byte[] wav = generateSyntheticWav(16000, 1.0, true, false);
        var result = analyzer.analyze(wav);

        assertThat(result.audioAnalyzed()).isTrue();
        assertThat(result.detectedCadence()).isEqualTo("NATURAL_HUMAN");
        assertThat(result.syntheticVoiceScore()).isLessThan(50.0);
    }

    @Test
    @DisplayName("flags synthetic speech with digital zero pauses and vocoder cutoff")
    void flagsSyntheticVoice() {
        byte[] wav = generateSyntheticWav(16000, 1.0, false, true);
        var result = analyzer.analyze(wav);

        assertThat(result.audioAnalyzed()).isTrue();
        assertThat(result.syntheticVoiceScore()).isGreaterThanOrEqualTo(50.0);
        assertThat(result.breathingPauseRatio()).isGreaterThan(0.05);
    }

    private byte[] generateSyntheticWav(int sampleRate, double durationSec, boolean addMicroTremor, boolean insertDigitalZeros) {
        int sampleCount = (int) (sampleRate * durationSec);
        ByteBuffer buffer = ByteBuffer.allocate(44 + sampleCount * 2).order(ByteOrder.LITTLE_ENDIAN);

        // RIFF header
        buffer.put("RIFF".getBytes());
        buffer.putInt(36 + sampleCount * 2);
        buffer.put("WAVE".getBytes());
        buffer.put("fmt ".getBytes());
        buffer.putInt(16); // subchunk1 size
        buffer.putShort((short) 1); // PCM
        buffer.putShort((short) 1); // mono
        buffer.putInt(sampleRate);
        buffer.putInt(sampleRate * 2); // byte rate
        buffer.putShort((short) 2); // block align
        buffer.putShort((short) 16); // bits per sample
        buffer.put("data".getBytes());
        buffer.putInt(sampleCount * 2);

        for (int i = 0; i < sampleCount; i++) {
            if (insertDigitalZeros && i % 4000 < 1000) {
                // Exact digital zero silence
                buffer.putShort((short) 0);
            } else {
                double freq = 220.0;
                if (addMicroTremor) {
                    freq += Math.sin(i * 0.05) * 5.0; // Vocal jitter
                }
                double val = Math.sin(2.0 * Math.PI * freq * i / sampleRate);
                if (addMicroTremor) {
                    val += (Math.random() - 0.5) * 0.05; // High-frequency ambient noise
                }
                buffer.putShort((short) (val * 16000));
            }
        }

        return buffer.array();
    }
}
