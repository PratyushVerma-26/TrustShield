package com.trustshield.gateway.controller;

import com.trustshield.gateway.config.GatewayProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.URI;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

/**
 * Transparent reverse proxy forwarding requests to the appropriate TrustShield microservice.
 *
 * <p>Implements the single origin pattern. Rather than the React console or mobile app
 * juggling seven ports (8083-8089) and multiple CORS origins, all traffic flows through
 * port 8080. If a downstream service is down or not yet started, the proxy returns a
 * structured, honest 503 rather than failing abruptly.
 */
@RestController
public class GatewayProxyController {

    private static final Logger log = LoggerFactory.getLogger(GatewayProxyController.class);

    private static final Set<String> HOP_BY_HOP_HEADERS = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
    );

    private final RestClient restClient;
    private final GatewayProperties properties;

    public GatewayProxyController(RestClient restClient, GatewayProperties properties) {
        this.restClient = restClient;
        this.properties = properties;
    }

    @RequestMapping(value = {
            "/api/v1/phishing/**",
            "/api/v1/breach/**",
            "/api/v1/deepfake/**",
            "/api/v1/misinformation/**",
            "/api/v1/fakenews/**",
            "/api/v1/integrity/**",
            "/api/v1/ledger/**",
            "/api/v1/fusion/**",
            "/api/v1/bot/**",
            "/webhook/**"
    })
    public ResponseEntity<?> proxy(
            HttpMethod method,
            HttpServletRequest request,
            @RequestBody(required = false) byte[] body
    ) {
        String path = request.getRequestURI();
        String query = request.getQueryString();
        String targetBaseUrl = resolveTargetBaseUrl(path);

        if (targetBaseUrl == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("error", "NO_ROUTE_FOR_PATH", "path", path));
        }

        String targetUriStr = targetBaseUrl + path + (query != null ? "?" + query : "");
        URI targetUri = URI.create(targetUriStr);

        try {
            var requestSpec = restClient.method(method)
                    .uri(targetUri);

            // Copy request headers
            Enumeration<String> headerNames = request.getHeaderNames();
            if (headerNames != null) {
                while (headerNames.hasMoreElements()) {
                    String name = headerNames.nextElement();
                    if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                        Collections.list(request.getHeaders(name))
                                .forEach(value -> requestSpec.header(name, value));
                    }
                }
            }

            if (body != null && body.length > 0) {
                requestSpec.body(body);
            }

            return requestSpec.exchange((clientRequest, clientResponse) -> {
                HttpHeaders responseHeaders = new HttpHeaders();
                clientResponse.getHeaders().forEach((name, values) -> {
                    if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase())) {
                        responseHeaders.put(name, values);
                    }
                });

                byte[] responseBytes = clientResponse.getBody().readAllBytes();
                return ResponseEntity.status(clientResponse.getStatusCode())
                        .headers(responseHeaders)
                        .body(responseBytes);
            });

        } catch (ResourceAccessException e) {
            log.warn("Downstream service unreachable for path {}: {}", path, e.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "error", "SERVICE_UNAVAILABLE",
                            "message", "Target microservice is not reachable: " + targetBaseUrl,
                            "path", path,
                            "degraded", true
                    ));
        } catch (RestClientResponseException e) {
            return ResponseEntity.status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(e.getResponseBodyAsByteArray());
        } catch (Exception e) {
            log.error("Proxy routing error for path {}: {}", path, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of(
                            "error", "BAD_GATEWAY",
                            "message", "Error proxying request to " + targetBaseUrl + ": " + e.getMessage(),
                            "path", path
                    ));
        }
    }

    private String resolveTargetBaseUrl(String path) {
        GatewayProperties.Services services = properties.services();
        if (path.startsWith("/api/v1/phishing")) {
            return services.phishingUrl();
        }
        if (path.startsWith("/api/v1/breach")) {
            return services.breachUrl();
        }
        if (path.startsWith("/api/v1/deepfake")) {
            return services.deepfakeUrl();
        }
        if (path.startsWith("/api/v1/misinformation") || path.startsWith("/api/v1/fakenews")) {
            return services.fakenewsUrl();
        }
        if (path.startsWith("/api/v1/integrity") || path.startsWith("/api/v1/ledger")) {
            return services.integrityUrl();
        }
        if (path.startsWith("/api/v1/fusion")) {
            return services.fusionUrl();
        }
        if (path.startsWith("/api/v1/bot") || path.startsWith("/webhook")) {
            return services.botUrl();
        }
        return null;
    }
}
