package com.trustshield.breach.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request to check an email address against known breaches.
 *
 * <p>Unlike the password check, this operation has no k-anonymity available: if
 * the lookup runs at all, the full address goes to a third party. The response
 * reports {@code kAnonymous=false} so a UI can warn the user before the call
 * rather than after, which is what the DPDP Act's notice expectation implies.
 *
 * <p>{@code toString} is redacted for the same reason as
 * {@link PasswordCheckRequest}: an email address is personal data, and logging it
 * by accident is a disclosure.
 *
 * @param email        the address to look up
 * @param acknowledged the caller's explicit confirmation that it understands the
 *                     address will be transmitted. The service refuses the lookup
 *                     without it, so consent is structural rather than a checkbox
 *                     the backend ignores.
 */
public record EmailCheckRequest(

        @NotBlank(message = "email must not be blank")
        @Email(message = "email must be a valid address")
        @Size(max = 320, message = "email must be at most 320 characters")
        String email,

        boolean acknowledged
) {

    @Override
    public String toString() {
        return "EmailCheckRequest[email=<redacted>, acknowledged=" + acknowledged + "]";
    }
}
