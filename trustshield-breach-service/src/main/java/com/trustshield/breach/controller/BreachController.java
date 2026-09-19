package com.trustshield.breach.controller;

import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.trustshield.breach.dto.BreachHistoryItem;
import com.trustshield.breach.dto.EmailCheckRequest;
import com.trustshield.breach.dto.EmailCheckResponse;
import com.trustshield.breach.dto.PasswordCheckRequest;
import com.trustshield.breach.dto.PasswordCheckResponse;
import com.trustshield.breach.service.BreachAuditService;
import com.trustshield.breach.service.EmailBreachService;
import com.trustshield.breach.service.PasswordExposureService;

/**
 * Breach monitoring endpoints.
 *
 * <p>Both checks are {@code POST} even though the email one is conceptually a
 * lookup, because a {@code GET} would put the secret in the URL, and URLs end up
 * in access logs, browser history, referrer headers and proxy caches. That is the
 * kind of leak that survives long after the request does.
 *
 * <p>The two endpoints are deliberately not unified behind one
 * {@code /check?type=} parameter. They have different privacy properties,
 * different configuration requirements and different consent obligations, and a
 * shared entry point would invite a caller to assume they are interchangeable.
 */
@RestController
@RequestMapping("/api/v1/breach")
@Tag(name = "Breach Monitoring",
        description = "Password exposure via k-anonymous lookup, and email breach lookup "
                + "which is not k-anonymous and says so")
public class BreachController {

    private final PasswordExposureService passwordService;
    private final EmailBreachService emailService;
    private final BreachAuditService auditService;

    public BreachController(PasswordExposureService passwordService,
                            EmailBreachService emailService,
                            BreachAuditService auditService) {
        this.passwordService = passwordService;
        this.emailService = emailService;
        this.auditService = auditService;
    }

    @PostMapping("/password")
    @Operation(summary = "Check a password for exposure",
            description = "Neither the password nor its full hash leaves this process. Only the "
                    + "first 5 hex characters of the SHA-1 are ever transmitted, and only if the "
                    + "range API is enabled; the bundled offline list works with no network at "
                    + "all. A confirmed corpus hit floors the risk score regardless of how strong "
                    + "the password looks, because a leaked password's structure is irrelevant.")
    public ResponseEntity<PasswordCheckResponse> checkPassword(
            @Valid @RequestBody PasswordCheckRequest request) {
        return ResponseEntity.ok(passwordService.check(request));
    }

    @PostMapping("/email")
    @Operation(summary = "Check an email address for exposure",
            description = "This transmits the FULL email address to a third-party API and is not "
                    + "k-anonymous. It therefore requires \"acknowledged\": true in the request "
                    + "body and a configured HIBP API key; without either it refuses rather than "
                    + "silently proceeding. Disabled by default.")
    public ResponseEntity<EmailCheckResponse> checkEmail(
            @Valid @RequestBody EmailCheckRequest request) {
        return ResponseEntity.ok(emailService.check(request));
    }

    @GetMapping("/history")
    @Operation(summary = "Recent checks",
            description = "The 25 most recent audit rows. Shows bucket prefixes and truncated "
                    + "subject hashes; the underlying table holds no passwords or addresses.")
    public ResponseEntity<List<BreachHistoryItem>> history() {
        return ResponseEntity.ok(auditService.recentChecks());
    }

    @GetMapping("/stats")
    @Operation(summary = "Dashboard counters",
            description = "Includes degradedChecks, so it is visible how often a source could "
                    + "not be reached rather than only how often something was found.")
    public ResponseEntity<Map<String, Object>> stats() {
        return ResponseEntity.ok(auditService.stats());
    }

    @GetMapping("/privacy")
    @Operation(summary = "Privacy card",
            description = "States, per endpoint, exactly what is transmitted and what is stored. "
                    + "Served as data so the dashboard cannot describe the guarantees "
                    + "differently from the implementation.")
    public ResponseEntity<Map<String, Object>> privacy() {
        return ResponseEntity.ok(auditService.privacyCard());
    }
}
