package com.trustshield.gateway.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * High-performance, memory-efficient sliding token bucket rate limiter.
 *
 * <p>Protects threat detection microservices against Denial of Service (DoS) and
 * high-volume automated brute-force attacks by bounding requests per IP address.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RateLimitingFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private static final int MAX_BURST = 100;
    private static final int REFILL_PER_MINUTE = 60;
    private static final long CLEANUP_INTERVAL_MS = 600_000L;

    private static class ClientBucket {
        double tokens;
        long lastRefillTime;

        ClientBucket(double tokens, long lastRefillTime) {
            this.tokens = tokens;
            this.lastRefillTime = lastRefillTime;
        }

        synchronized boolean tryConsume() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTime;
            if (elapsed > 0) {
                double refill = (elapsed / 60000.0) * REFILL_PER_MINUTE;
                tokens = Math.min(MAX_BURST, tokens + refill);
                lastRefillTime = now;
            }

            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }
    }

    private final ConcurrentHashMap<String, ClientBucket> clientBuckets = new ConcurrentHashMap<>();
    private volatile long lastCleanupTime = System.currentTimeMillis();
    private final AtomicInteger requestCounter = new AtomicInteger(0);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request instanceof HttpServletRequest httpRequest && response instanceof HttpServletResponse httpResponse) {
            String path = httpRequest.getRequestURI();

            if (isExemptPath(path)) {
                chain.doFilter(request, response);
                return;
            }

            String clientIp = resolveClientIp(httpRequest);
            ClientBucket bucket = clientBuckets.computeIfAbsent(clientIp, k -> new ClientBucket(MAX_BURST, System.currentTimeMillis()));

            if (!bucket.tryConsume()) {
                log.warn("Rate limit exceeded for client IP: {} on path: {}", clientIp, path);
                httpResponse.setStatus(429);
                httpResponse.setHeader("Retry-After", "60");
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write(
                        "{\"error\":\"TOO_MANY_REQUESTS\",\"message\":\"Rate limit exceeded. Maximum 60 requests per minute allowed. Please wait before retrying.\",\"path\":\"" + path + "\"}"
                );
                return;
            }

            if (requestCounter.incrementAndGet() % 500 == 0) {
                cleanupOldEntries();
            }
        }

        chain.doFilter(request, response);
    }

    private boolean isExemptPath(String path) {
        if (path == null) return false;
        return path.startsWith("/assets/")
                || path.equals("/")
                || path.equals("/index.html")
                || path.equals("/chat.html")
                || path.equals("/favicon.ico")
                || path.startsWith("/actuator/health");
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int commaIdx = forwarded.indexOf(',');
            return (commaIdx != -1 ? forwarded.substring(0, commaIdx) : forwarded).trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
    }

    private void cleanupOldEntries() {
        long now = System.currentTimeMillis();
        if (now - lastCleanupTime > CLEANUP_INTERVAL_MS) {
            lastCleanupTime = now;
            clientBuckets.entrySet().removeIf(entry -> (now - entry.getValue().lastRefillTime) > CLEANUP_INTERVAL_MS);
        }
    }
}