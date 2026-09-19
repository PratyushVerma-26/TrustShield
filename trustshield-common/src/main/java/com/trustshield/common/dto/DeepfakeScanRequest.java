package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Request to perform forensic analysis on an image or video file.
 *
 * @param incidentId optional cross-modal correlation ID
 * @param imageBase64 base64-encoded image or video payload
 * @param filename original filename, used for format identification
 * @param mimeType declared MIME type (e.g. "image/jpeg", "video/mp4", "audio/wav")
 * @param context optional source context (e.g. "WHATSAPP_ATTACHMENT", "WEB_UPLOAD")
 * @param mediaType optional media category ("IMAGE", "VIDEO", "AUDIO", or auto-detected)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DeepfakeScanRequest(
        IncidentId incidentId,
        String imageBase64,
        String filename,
        String mimeType,
        String context,
        String mediaType
) {
    public DeepfakeScanRequest(IncidentId incidentId, String imageBase64, String filename, String mimeType, String context) {
        this(incidentId, imageBase64, filename, mimeType, context, detectMediaType(filename, mimeType));
    }

    public DeepfakeScanRequest {
        incidentId = incidentId != null ? incidentId : IncidentId.generate();
        mediaType = mediaType != null ? mediaType : detectMediaType(filename, mimeType);
    }

    private static String detectMediaType(String filename, String mimeType) {
        if (mimeType != null) {
            String lower = mimeType.toLowerCase();
            if (lower.startsWith("video/")) return "VIDEO";
            if (lower.startsWith("audio/")) return "AUDIO";
            if (lower.startsWith("image/")) return "IMAGE";
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".mp4") || lower.endsWith(".mov") || lower.endsWith(".avi") ||
                lower.endsWith(".webm") || lower.endsWith(".mkv")) {
                return "VIDEO";
            }
            if (lower.endsWith(".wav") || lower.endsWith(".mp3") || lower.endsWith(".aac") ||
                lower.endsWith(".ogg") || lower.endsWith(".m4a")) {
                return "AUDIO";
            }
        }
        return "IMAGE";
    }
}
