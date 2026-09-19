package com.trustshield.gateway.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Injects essential OWASP HTTP security headers into all responses passing through the Gateway.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse httpResponse) {
            // Prevent MIME-sniffing
            httpResponse.setHeader("X-Content-Type-Options", "nosniff");
            // Prevent Clickjacking
            httpResponse.setHeader("X-Frame-Options", "SAMEORIGIN");
            // Referrer policy
            httpResponse.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            // Restrict sensitive browser APIs
            httpResponse.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        }
        chain.doFilter(request, response);
    }
}