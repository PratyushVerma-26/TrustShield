package com.trustshield.breach.controller;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns exceptions into stable JSON.
 *
 * <p>This is a near-copy of the phishing service's handler with one extra
 * concern, and the difference is the reason it is not simply shared: the request
 * bodies here contain secrets.
 *
 * <p>Spring's default validation error rendering includes the
 * <em>rejected value</em> for a failed field. On a phishing scan that is a URL,
 * which is unwelcome in a log but survivable. Here it would be a password. So
 * {@link #handleValidation} reports the field name and the constraint message
 * only, and additionally drops any message that happens to contain the rejected
 * value — a belt-and-braces guard against a future custom constraint whose
 * message interpolates {@code ${validatedValue}}.
 *
 * <p>As in the phishing service, stack traces and internal exception messages are
 * never returned to the caller.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException e) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField() + ": " + safeMessage(f.getDefaultMessage(), f.getRejectedValue()))
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, "VALIDATION_FAILED",
                detail.isEmpty() ? "Request body failed validation" : detail);
    }

    /**
     * Returns the constraint message, unless it contains the rejected value.
     *
     * <p>Standard Bean Validation messages ("must not be blank", "size must be
     * between 0 and 256") never embed the value, so in practice this passes them
     * through unchanged. The check exists so that adding a constraint whose
     * message does embed the value cannot quietly turn a validation error into a
     * password disclosure.
     */
    private static String safeMessage(String message, Object rejectedValue) {
        if (message == null || message.isBlank()) {
            return "is invalid";
        }
        if (rejectedValue instanceof CharSequence value
                && !value.isEmpty()
                && message.contains(value)) {
            return "is invalid";
        }
        return message;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e) {
        // The message here is written by our own code, never built from input.
        return build(HttpStatus.BAD_REQUEST, "INVALID_INPUT", e.getMessage());
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalState(IllegalStateException e) {
        log.error("Service in an invalid state", e);
        return build(HttpStatus.SERVICE_UNAVAILABLE, "SERVICE_NOT_READY",
                "The breach monitoring service is not ready to answer requests.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception e) {
        log.error("Unhandled exception while processing request", e);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR",
                "An unexpected error occurred. The incident has been logged.");
    }

    private static ResponseEntity<Map<String, Object>> build(HttpStatus status,
                                                             String code,
                                                             String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("code", code);
        body.put("message", message);
        return ResponseEntity.status(status).body(body);
    }
}
