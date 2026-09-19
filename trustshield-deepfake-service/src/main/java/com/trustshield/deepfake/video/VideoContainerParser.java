package com.trustshield.deepfake.video;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Pure Java ISO Base Media File Format (MP4 / QuickTime / MOV) and WebM container parser.
 *
 * <p>Inspects container header boxes without external FFmpeg/native dependencies:
 * <ul>
 *   <li>Traverses {@code ftyp}, {@code moov}, {@code trak}, {@code mdia}, {@code hdlr} boxes.</li>
 *   <li>Detects presence of separate video and audio tracks.</li>
 *   <li>Scans metadata atoms for video editing suites (Adobe Premiere, Final Cut, DaVinci)
 *       or generative AI video toolchains (DeepFaceLab, FaceSwap, Runway, Synthesia).</li>
 * </ul>
 */
@Component
public class VideoContainerParser {

    private static final Logger log = LoggerFactory.getLogger(VideoContainerParser.class);

    private static final List<String> EDITING_AND_AI_MARKERS = List.of(
            "deepfacelab", "faceswap", "synthesia", "runway", "pika", "sora", "heygen", "d-id",
            "premiere", "after effects", "final cut", "davinci", "ffmpeg", "lavf", "handbrake", "capcut"
    );

    public record VideoContainerInfo(
            boolean isVideoContainer,
            String format,
            boolean hasVideoTrack,
            boolean hasAudioTrack,
            int trackCount,
            String editingSoftware,
            long durationMs
    ) {
        public static VideoContainerInfo nonVideo() {
            return new VideoContainerInfo(false, "NONE", false, false, 0, null, 0L);
        }
    }

    /**
     * Parses the supplied raw byte array to extract container topology and metadata.
     */
    public VideoContainerInfo parse(byte[] bytes) {
        if (bytes == null || bytes.length < 12) {
            return VideoContainerInfo.nonVideo();
        }

        // 1. Check for WebM / Matroska EBML signature: 0x1A 0x45 0xDF 0xA3
        if ((bytes[0] & 0xFF) == 0x1A && (bytes[1] & 0xFF) == 0x45 &&
            (bytes[2] & 0xFF) == 0xDF && (bytes[3] & 0xFF) == 0xA3) {
            String software = scanForSoftwareStrings(bytes, 0, Math.min(bytes.length, 4096));
            return new VideoContainerInfo(true, "WEBM", true, true, 2, software, 0L);
        }

        // 2. Check for ISO BMFF ftyp box at offset 4
        int offset = 0;
        boolean hasFtyp = false;
        String majorBrand = "MP4";

        while (offset + 8 <= bytes.length) {
            long boxSize = readUint32(bytes, offset);
            String boxType = readString(bytes, offset + 4, 4);

            if (boxSize == 0) {
                // Box extends to EOF
                boxSize = bytes.length - offset;
            } else if (boxSize == 1) {
                // Extended 64-bit size
                if (offset + 16 > bytes.length) break;
                boxSize = readUint64(bytes, offset + 8);
                if (boxSize < 16) break;
            }

            if (boxSize < 8 || offset + boxSize > bytes.length) {
                break;
            }

            if ("ftyp".equals(boxType)) {
                hasFtyp = true;
                if (offset + 12 <= bytes.length) {
                    majorBrand = readString(bytes, offset + 8, 4).trim();
                }
                break;
            }

            offset += (int) boxSize;
        }

        if (!hasFtyp) {
            // Also check if RIFF AVI
            if (bytes.length >= 12 && "RIFF".equals(readString(bytes, 0, 4)) && "AVI ".equals(readString(bytes, 8, 4))) {
                String software = scanForSoftwareStrings(bytes, 0, Math.min(bytes.length, 4096));
                return new VideoContainerInfo(true, "AVI", true, true, 2, software, 0L);
            }
            return VideoContainerInfo.nonVideo();
        }

        // 3. Walk boxes looking for moov -> trak -> mdia -> hdlr
        boolean hasVideo = false;
        boolean hasAudio = false;
        int trackCount = 0;
        long durationMs = 0L;
        String editingSoftware = null;

        offset = 0;
        while (offset + 8 <= bytes.length) {
            long boxSize = readUint32(bytes, offset);
            String boxType = readString(bytes, offset + 4, 4);

            if (boxSize == 0) {
                boxSize = bytes.length - offset;
            } else if (boxSize == 1) {
                if (offset + 16 > bytes.length) break;
                boxSize = readUint64(bytes, offset + 8);
            }

            if (boxSize < 8 || offset + boxSize > bytes.length) {
                break;
            }

            if ("moov".equals(boxType)) {
                // Scan inside moov container
                int moovStart = offset + 8;
                int moovEnd = offset + (int) boxSize;
                int subOffset = moovStart;

                while (subOffset + 8 <= moovEnd) {
                    long subSize = readUint32(bytes, subOffset);
                    String subType = readString(bytes, subOffset + 4, 4);

                    if (subSize < 8 || subOffset + subSize > moovEnd) break;

                    if ("trak".equals(subType)) {
                        trackCount++;
                        // Scan trak for hdlr (handler)
                        String handlerType = findHandlerTypeInTrack(bytes, subOffset + 8, subOffset + (int) subSize);
                        if ("vide".equals(handlerType)) {
                            hasVideo = true;
                        } else if ("soun".equals(handlerType)) {
                            hasAudio = true;
                        }
                    } else if ("mvhd".equals(subType)) {
                        durationMs = parseMovieHeaderDuration(bytes, subOffset + 8, subOffset + (int) subSize);
                    }

                    subOffset += (int) subSize;
                }
            }

            // Check udta or whole header for software signatures
            if (editingSoftware == null && ("udta".equals(boxType) || "meta".equals(boxType))) {
                editingSoftware = scanForSoftwareStrings(bytes, offset + 8, offset + (int) boxSize);
            }

            offset += (int) boxSize;
        }

        // Fallback software scan across container prefix (up to first 8KB)
        if (editingSoftware == null) {
            editingSoftware = scanForSoftwareStrings(bytes, 0, Math.min(bytes.length, 8192));
        }

        // If no explicit tracks parsed from moov, default to true if ftyp was verified
        if (!hasVideo && hasFtyp) {
            hasVideo = true;
            trackCount = Math.max(1, trackCount);
        }

        return new VideoContainerInfo(true, majorBrand, hasVideo, hasAudio, trackCount, editingSoftware, durationMs);
    }

    private String findHandlerTypeInTrack(byte[] bytes, int start, int end) {
        int off = start;
        while (off + 8 <= end) {
            long size = readUint32(bytes, off);
            String type = readString(bytes, off + 4, 4);
            if (size < 8 || off + size > end) break;

            if ("mdia".equals(type)) {
                int mdiaOff = off + 8;
                int mdiaEnd = off + (int) size;
                while (mdiaOff + 8 <= mdiaEnd) {
                    long subSize = readUint32(bytes, mdiaOff);
                    String subType = readString(bytes, mdiaOff + 4, 4);
                    if (subSize < 8 || mdiaOff + subSize > mdiaEnd) break;

                    if ("hdlr".equals(subType) && mdiaOff + 16 <= mdiaEnd) {
                        // In hdlr: 4 bytes version/flags, 4 bytes pre_defined, 4 bytes handler_type
                        return readString(bytes, mdiaOff + 16, 4).toLowerCase(Locale.ROOT);
                    }
                    mdiaOff += (int) subSize;
                }
            }
            off += (int) size;
        }
        return "unknown";
    }

    private long parseMovieHeaderDuration(byte[] bytes, int start, int end) {
        if (start + 24 > end) return 0L;
        int version = bytes[start] & 0xFF;
        if (version == 0 && start + 24 <= end) {
            long timescale = readUint32(bytes, start + 12);
            long duration = readUint32(bytes, start + 16);
            if (timescale > 0) {
                return (duration * 1000L) / timescale;
            }
        }
        return 0L;
    }

    private String scanForSoftwareStrings(byte[] bytes, int start, int end) {
        int length = Math.max(0, end - start);
        if (length <= 0) return null;
        String text = new String(bytes, start, length, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);

        for (String marker : EDITING_AND_AI_MARKERS) {
            if (text.contains(marker)) {
                return marker.toUpperCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static long readUint32(byte[] b, int offset) {
        return ((long) (b[offset] & 0xFF) << 24) |
               ((long) (b[offset + 1] & 0xFF) << 16) |
               ((long) (b[offset + 2] & 0xFF) << 8) |
               ((long) (b[offset + 3] & 0xFF));
    }

    private static long readUint64(byte[] b, int offset) {
        long high = readUint32(b, offset);
        long low = readUint32(b, offset + 4);
        return (high << 32) | (low & 0xFFFFFFFFL);
    }

    private static String readString(byte[] b, int offset, int len) {
        if (offset + len > b.length) len = b.length - offset;
        if (len <= 0) return "";
        return new String(b, offset, len, StandardCharsets.US_ASCII);
    }
}
