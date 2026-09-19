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
 * Global exception handler providing standardized error responses.
 *
 * <p>Sanitizes error output to prevent credential or sensitive parameter leakage:
 * <ul>
 *   <li>Validation messages strip rejected values so passwords are never logged or returned.</li>
 *   <li>Internal exception details and stack traces are suppressed from client responses.</li>
 * </ul>
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
     * Sanitizes constraint messages by filtering out any occurrence of rejected values.
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
