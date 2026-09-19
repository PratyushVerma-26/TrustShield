package com.trustshield.breach.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request to check a password against breach corpora.
 *
 * <p><strong>{@code toString} is overridden deliberately.</strong> Records
 * generate a {@code toString} that includes every component, so a single
 * {@code log.info("request={}", request)} — or an exception message built by a
 * framework that calls {@code toString} on arguments — would write the user's
 * password to the log file in plaintext. Redacting it here means the leak cannot
 * happen even by accident, at any call site, including ones written later.
 *
 * <p>The password is also never persisted. {@code BreachCheckRecord} stores only
 * the 5-character k-anonymity bucket prefix, which is deliberately
 * non-identifying.
 *
 * @param password the candidate to check. Hashed immediately, never stored, and
 *                 never transmitted in full to any third party.
 * @param context  optional hint about where this came from, for the audit trail
 */
public record PasswordCheckRequest(

        @NotBlank(message = "password must not be blank")
        @Size(max = 256, message = "password must be at most 256 characters")
        String password,

        @Size(max = 32, message = "context must be at most 32 characters")
        String context
) {

    @Override
    public String toString() {
        return "PasswordCheckRequest[password=<redacted>, context=" + context + "]";
    }
}
