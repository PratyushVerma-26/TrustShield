# Multi-stage Dockerfile for TrustShield Enterprise Microservices
# Optimized for minimal container footprint, layer caching, and non-root execution.

# ==============================================================================
# Stage 1: Build the Maven reactor
# ==============================================================================
FROM maven:3.9-eclipse-temurin-21-alpine AS builder

WORKDIR /workspace

# Copy parent POM and module POMs to leverage Docker layer caching for dependencies
COPY pom.xml .
COPY trustshield-common/pom.xml trustshield-common/
COPY trustshield-gateway/pom.xml trustshield-gateway/
COPY trustshield-phishing-service/pom.xml trustshield-phishing-service/
COPY trustshield-breach-service/pom.xml trustshield-breach-service/
COPY trustshield-deepfake-service/pom.xml trustshield-deepfake-service/
COPY trustshield-fakenews-service/pom.xml trustshield-fakenews-service/
COPY trustshield-integrity-service/pom.xml trustshield-integrity-service/
COPY trustshield-fusion-service/pom.xml trustshield-fusion-service/
COPY trustshield-bot-service/pom.xml trustshield-bot-service/

# Cache Maven dependencies
RUN mvn dependency:go-offline -B -q || true

# Copy all module source trees
COPY trustshield-common/src trustshield-common/src
COPY trustshield-gateway/src trustshield-gateway/src
COPY trustshield-phishing-service/src trustshield-phishing-service/
COPY trustshield-breach-service/src trustshield-breach-service/
COPY trustshield-deepfake-service/src trustshield-deepfake-service/
COPY trustshield-fakenews-service/src trustshield-fakenews-service/
COPY trustshield-integrity-service/src trustshield-integrity-service/
COPY trustshield-fusion-service/src trustshield-fusion-service/
COPY trustshield-bot-service/src trustshield-bot-service/

# Package all microservices (tests executed in CI pipeline)
RUN mvn clean package -DskipTests -B -q

# ==============================================================================
# Stage 2: Minimal Distroless / Alpine JRE Runtime
# ==============================================================================
FROM eclipse-temurin:21-jre-alpine AS runtime

ARG SERVICE_NAME=trustshield-gateway
ARG SERVICE_PORT=8080

ENV SERVICE_NAME=${SERVICE_NAME}
ENV SERVER_PORT=${SERVICE_PORT}

# Security hardening: Unprivileged execution
RUN addgroup -S trustshield && adduser -S trustshield -G trustshield

# Install curl for container health check
RUN apk add --no-cache curl

WORKDIR /app

# Copy the built fat JAR for the parameterized service
COPY --from=builder --chown=trustshield:trustshield /workspace/${SERVICE_NAME}/target/${SERVICE_NAME}-*.jar app.jar

USER trustshield

EXPOSE ${SERVICE_PORT}

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:${SERVER_PORT}/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
