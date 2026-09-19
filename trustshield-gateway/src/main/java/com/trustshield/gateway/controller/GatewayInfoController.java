package com.trustshield.gateway.controller;

import com.trustshield.gateway.config.GatewayProperties;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Root metadata endpoint reporting gateway configuration and service route mappings.
 */
@RestController
public class GatewayInfoController {

    private final GatewayProperties properties;

    public GatewayInfoController(GatewayProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/api/v1/gateway/routes")
    public ResponseEntity<Map<String, Object>> getRoutes() {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", "TrustShield Unified API Gateway");
        info.put("port", 8080);
        info.put("routes", Map.of(
                "phishing", properties.services().phishingUrl(),
                "breach", properties.services().breachUrl(),
                "deepfake", properties.services().deepfakeUrl(),
                "fakenews", properties.services().fakenewsUrl(),
                "integrity", properties.services().integrityUrl(),
                "fusion", properties.services().fusionUrl(),
                "bot", properties.services().botUrl()
        ));
        info.put("corsOrigins", properties.cors().allowedOrigins());
        return ResponseEntity.ok(info);
    }
}
