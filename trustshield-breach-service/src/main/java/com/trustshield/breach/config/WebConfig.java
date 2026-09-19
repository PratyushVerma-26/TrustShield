package com.trustshield.breach.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * Permissive CORS so the standalone dashboard HTML can call this service
     * directly when opened from the filesystem or another port.
     *
     * <p>Appropriate for a local demonstration and wrong in production: a
     * deployed build should list the dashboard's exact origin. Flagged here
     * rather than left as a silent hole for a reviewer to find.
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOriginPatterns("*")
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }

    @Bean
    public OpenAPI breachOpenApi() {
        return new OpenAPI().info(new Info()
                .title("TrustShield Breach Monitoring API")
                .version("1.0.0")
                .description("""
                        Credential exposure checking for the TrustShield threat detection platform.

                        The two endpoints here have genuinely different privacy properties, and \
                        the API reports which applies rather than asserting one for both. \
                        POST /password implements the Pwned Passwords range protocol: the SHA-1 \
                        is computed locally, only its first 5 hex characters are ever sent, and \
                        the remaining 35 are matched in-process. The server learns one bucket in \
                        16^5, so it cannot tell which password was queried. POST /email has no \
                        such property: the breached-account API takes the full address and there \
                        is no prefix variant, so that endpoint requires explicit acknowledgement \
                        and reports kAnonymous=false.

                        Scoring inverts the phishing module's weighting. There, the model is \
                        primary and blocklists corroborate. Here, corpus membership is primary \
                        and structural analysis corroborates, because a corpus hit is direct \
                        evidence that the exact string is in an attacker's wordlist rather than a \
                        prediction about it. A hit floors the score; structure alone is capped \
                        below DANGEROUS. A source that cannot be reached yields UNAVAILABLE and a \
                        degraded verdict, never a clean one."""));
    }
}
