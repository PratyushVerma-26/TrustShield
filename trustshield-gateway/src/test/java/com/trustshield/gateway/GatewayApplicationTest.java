package com.trustshield.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class GatewayApplicationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads() {
    }

    @Test
    void actuatorHealthReturnsOk() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void routesEndpointReturnsMetadata() throws Exception {
        mockMvc.perform(get("/api/v1/gateway/routes"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.port").value(8080))
                .andExpect(jsonPath("$.routes.phishing").exists());
    }

    @Test
    void corsPreflightHeadersApplied() throws Exception {
        mockMvc.perform(options("/api/v1/gateway/routes")
                        .header("Origin", "http://localhost:5173")
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }

    @Test
    void unreachableDownstreamReturnsHonest503() throws Exception {
        // Ports 8085 (deepfake) isn't running in test context, proxy should return 503 degraded
        mockMvc.perform(post("/api/v1/deepfake/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"imageBase64\":\"dGVzdA==\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("SERVICE_UNAVAILABLE"))
                .andExpect(jsonPath("$.degraded").value(true));
    }
}
