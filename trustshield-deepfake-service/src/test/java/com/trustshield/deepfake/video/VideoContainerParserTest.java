package com.trustshield.deepfake.video;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class VideoContainerParserTest {

    private final VideoContainerParser parser = new VideoContainerParser();

    @Test
    @DisplayName("returns nonVideo for null, empty, or plain image bytes")
    void handlesNonVideo() {
        var emptyResult = parser.parse(new byte[0]);
        assertThat(emptyResult.isVideoContainer()).isFalse();

        var textResult = parser.parse("Hello World Not A Video".getBytes(StandardCharsets.UTF_8));
        assertThat(textResult.isVideoContainer()).isFalse();
    }

    @Test
    @DisplayName("correctly identifies MP4 ftyp container and major brand")
    void identifiesMp4Container() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // Write ftyp box: 4 bytes len (20), 4 bytes "ftyp", 4 bytes "isom", 4 bytes minor_ver, 4 bytes "mp42"
        baos.write(new byte[]{0, 0, 0, 20});
        baos.write("ftyp".getBytes(StandardCharsets.US_ASCII));
        baos.write("isom".getBytes(StandardCharsets.US_ASCII));
        baos.write(new byte[]{0, 0, 0, 1});
        baos.write("mp42".getBytes(StandardCharsets.US_ASCII));

        // Add dummy moov box
        baos.write(new byte[]{0, 0, 0, 16});
        baos.write("moov".getBytes(StandardCharsets.US_ASCII));
        baos.write(new byte[]{0, 0, 0, 8});
        baos.write("mvhd".getBytes(StandardCharsets.US_ASCII));

        var result = parser.parse(baos.toByteArray());
        assertThat(result.isVideoContainer()).isTrue();
        assertThat(result.format()).isEqualTo("isom");
        assertThat(result.hasVideoTrack()).isTrue();
    }

    @Test
    @DisplayName("detects generative AI editing markers in video metadata")
    void detectsAiEditingMarkers() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // ftyp box
        baos.write(new byte[]{0, 0, 0, 16});
        baos.write("ftyp".getBytes(StandardCharsets.US_ASCII));
        baos.write("mp42".getBytes(StandardCharsets.US_ASCII));
        baos.write(new byte[]{0, 0, 0, 0});

        // moov box containing udta with DeepFaceLab signature
        String marker = "Encoded with DeepFaceLab build 2026";
        byte[] markerBytes = marker.getBytes(StandardCharsets.ISO_8859_1);
        int udtaLen = 8 + markerBytes.length;

        baos.write(new byte[]{0, 0, (byte) ((udtaLen + 8) >> 8), (byte) (udtaLen + 8)});
        baos.write("moov".getBytes(StandardCharsets.US_ASCII));
        baos.write(new byte[]{0, 0, (byte) (udtaLen >> 8), (byte) udtaLen});
        baos.write("udta".getBytes(StandardCharsets.US_ASCII));
        baos.write(markerBytes);

        var result = parser.parse(baos.toByteArray());
        assertThat(result.isVideoContainer()).isTrue();
        assertThat(result.editingSoftware()).isEqualTo("DEEPFACELAB");
    }
}
