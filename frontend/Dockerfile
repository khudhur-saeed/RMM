# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: React / Vite Static Asset Builder
# ==============================================================================
FROM node:22-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ==============================================================================
# Stage 2: Unprivileged Nginx Production Runtime
# ==============================================================================
FROM nginxinc/nginx-unprivileged:stable-alpine AS runtime

# Copy custom hardened Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy compiled React production bundle from builder stage
COPY --from=builder --chown=nginx:nginx /build/dist /usr/share/nginx/html

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD ["wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:8080/healthz"]

CMD ["nginx", "-g", "daemon off;"]
