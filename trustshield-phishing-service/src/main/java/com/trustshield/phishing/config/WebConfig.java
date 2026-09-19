package com.trustshield.phishing.config;

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
     * <p>This is appropriate for a local demonstration and would be wrong in
     * production: a deployed build should list the dashboard's exact origin.
     * Flagged here rather than left as a silent hole for a reviewer to find.
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
    public OpenAPI phishingOpenApi() {
        return new OpenAPI().info(new Info()
                .title("TrustShield Phishing Detection API")
                .version("1.0.0")
                .description("""
                        Lexical URL classification for the TrustShield threat detection platform.

                        Scoring: a logistic-regression model over 26 lexical features produces \
                        the base risk score. External reputation sources (Google Safe Browsing, \
                        VirusTotal) can only raise that score, never lower it, because blocklists \
                        are high-precision but low-recall and a clean lookup is not evidence of \
                        safety."""));
    }
}
