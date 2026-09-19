package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Request to verify a text claim, image news, or video news item against misinformation sources.
 *
 * @param incidentId optional cross-modal correlation ID
 * @param claimText the text or headline to assess (optional if media provides textual headline)
 * @param context optional context (e.g. "WHATSAPP_FORWARD", "TWITTER_POST", "NEWS_BROADCAST")
 * @param mediaType media category ("TEXT", "IMAGE", "VIDEO")
 * @param mediaBase64 base64-encoded payload for image or video news
 * @param mediaFilename original filename of the news media
 * @param mediaMimeType declared MIME type (e.g. "image/jpeg", "video/mp4")
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClaimCheckRequest(
        IncidentId incidentId,
        String claimText,
        String context,
        String mediaType,
        String mediaBase64,
        String mediaFilename,
        String mediaMimeType
) {
    public ClaimCheckRequest(IncidentId incidentId, String claimText, String context) {
        this(incidentId, claimText, context, "TEXT", null, null, null);
    }

    public ClaimCheckRequest {
        incidentId = incidentId != null ? incidentId : IncidentId.generate();
        mediaType = mediaType != null ? mediaType : detectMediaType(mediaFilename, mediaMimeType, mediaBase64);
    }

    private static String detectMediaType(String filename, String mimeType, String base64) {
        if (mimeType != null) {
            String lower = mimeType.toLowerCase();
            if (lower.startsWith("video/")) return "VIDEO";
            if (lower.startsWith("image/")) return "IMAGE";
        }
        if (filename != null) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".mp4") || lower.endsWith(".mov") || lower.endsWith(".avi") || lower.endsWith(".webm")) {
                return "VIDEO";
            }
            if (lower.endsWith(".jpg") || lower.endsWith(".jpeg") || lower.endsWith(".png") || lower.endsWith(".webp")) {
                return "IMAGE";
            }
        }
        if (base64 != null && !base64.isBlank()) {
            return "IMAGE";
        }
        return "TEXT";
    }
}
