package com.trustshield.common.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

/**
 * Cross-modal correlation identifier.
 *
 * <p>Tracks an incident across multiple detection surfaces: a suspicious link,
 * an associated deepfake image, an accompanying misinformation claim, and any
 * credential breach checks. Passing this correlation ID binds disparate evidence
 * into a unified audit trail in the fusion service and integrity ledger.
 */
public record IncidentId(@JsonValue String value) implements Serializable {

    public IncidentId {
        Objects.requireNonNull(value, "Incident ID value must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("Incident ID value must not be blank");
        }
    }

    @JsonCreator
    public static IncidentId of(String value) {
        return new IncidentId(value);
    }

    public static IncidentId generate() {
        return new IncidentId("inc-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
    }

    @Override
    public String toString() {
        return value;
    }
}
