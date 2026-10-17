# Multi-stage Dockerfile for TrustShield Web Console Operations Cockpit
# Stage 1: Build the React 18 / TypeScript SPA
FROM node:20-alpine AS builder

WORKDIR /app

# Copy verdict-core first to satisfy the local file dependency
COPY packages/verdict-core/package*.json ./packages/verdict-core/
COPY packages/verdict-core/tsconfig.json ./packages/verdict-core/
COPY packages/verdict-core/src/ ./packages/verdict-core/src/

WORKDIR /app/packages/verdict-core
RUN npm ci && npm run build

# Copy and build web-console
WORKDIR /app/packages/web-console
COPY packages/web-console/package*.json ./
RUN npm ci

COPY packages/web-console/ ./

# Accept build-time argument for Gateway URL
ARG VITE_GATEWAY_URL=""
ENV VITE_GATEWAY_URL=${VITE_GATEWAY_URL}

RUN npm run build

# Stage 2: Minimal hardened Nginx runtime
FROM nginx:1.27-alpine AS runtime

# Remove default nginx index page
RUN rm -rf /usr/share/nginx/html/*

# Copy built SPA distribution from builder
COPY --from=builder /app/packages/web-console/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY packages/web-console/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O - http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
