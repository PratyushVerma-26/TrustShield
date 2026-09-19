package com.trustshield.phishing.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request to scan a single URL.
 *
 * @param url     the URL to assess. A scheme is optional; {@code sbi-verify.tk}
 *                is accepted as readily as {@code https://sbi-verify.tk}, because
 *                users paste links in both forms.
 * @param context optional hint about where the link came from
 *                ({@code EMAIL}, {@code SMS}, {@code BROWSER}, {@code SOCIAL}).
 *                Recorded for the audit trail and used by the fusion service; it
 *                does not affect the lexical score.
 */
public record ScanRequest(

        @NotBlank(message = "url must not be blank")
        @Size(max = 2048, message = "url must be at most 2048 characters")
        String url,

        @Size(max = 32, message = "context must be at most 32 characters")
        String context
) {
}
