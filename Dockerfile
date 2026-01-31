# syntax=docker/dockerfile:1.7
# Ultra-optimized Dockerfile - minimal runtime dependencies (no n8n packages)

# Stage 1: Builder (TypeScript compilation only)
FROM node:22-alpine AS builder
WORKDIR /app

# Copy tsconfig files for TypeScript compilation
COPY tsconfig*.json ./

# Create minimal package.json and install ONLY build dependencies
# Note: openai and zod are needed for TypeScript compilation of template metadata modules
RUN --mount=type=cache,target=/root/.npm \
    echo '{}' > package.json && \
    npm install --no-save --legacy-peer-deps typescript@^5.8.3 @types/node@^22.15.30 @types/express@^5.0.3 \
        @modelcontextprotocol/sdk@1.20.1 dotenv@^16.5.0 express@^5.1.0 axios@^1.10.0 \
        n8n-workflow@^2.4.2 uuid@^11.0.5 @types/uuid@^10.0.0 \
        openai@^4.77.0 zod@3.24.1 lru-cache@^11.2.1 @supabase/supabase-js@^2.57.4 \
        better-auth@^1.4.18 @better-auth/oauth-provider@^1.4.18

# Copy source and build
COPY src ./src
COPY package.json ./
# Note: src/n8n contains TypeScript types needed for compilation
# These will be compiled but not included in runtime
RUN npx tsc -p tsconfig.build.json

# Stage 2: Database Builder (builds nodes.db with full n8n packages)
FROM node:22-alpine AS db-builder
WORKDIR /app

# Install full package dependencies including n8n for database generation
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --legacy-peer-deps

# Copy built scripts and database schema
COPY --from=builder /app/dist/scripts ./dist/scripts
COPY --from=builder /app/dist/database ./dist/database
COPY src/database/schema-optimized.sql ./src/database/

# Generate nodes.db from installed n8n packages
# This takes ~2 minutes and creates ~70MB database
RUN mkdir -p ./data && \
    node dist/scripts/rebuild.js && \
    ls -lh ./data/nodes.db

# Stage 3: Runtime (minimal dependencies)
FROM node:22-alpine AS runtime
WORKDIR /app

# Install only essential runtime tools
RUN apk add --no-cache curl su-exec && \
    rm -rf /var/cache/apk/*

# Copy runtime-only package.json
COPY package.runtime.json package.json

# Install runtime dependencies with better-sqlite3 compilation
# Build tools (python3, make, g++) are installed, used for compilation, then removed
# This enables native SQLite (better-sqlite3) instead of sql.js, preventing memory leaks
RUN --mount=type=cache,target=/root/.npm \
    apk add --no-cache python3 make g++ && \
    npm install --production --no-audit --no-fund --legacy-peer-deps && \
    apk del python3 make g++

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist

# Copy pre-built nodes.db from database builder stage
# This database (~70MB) is generated from n8n packages at build time
COPY --from=db-builder /app/data/nodes.db ./data/nodes.db

# Copy database schema
COPY src/database/schema-optimized.sql ./src/database/
COPY .env.example ./

# Copy OAuth UI files for better-auth integration
COPY src/public ./dist/public

# Copy entrypoint script, config parser, OAuth scripts, and n8n-mcp command
COPY docker/docker-entrypoint.sh /usr/local/bin/
COPY docker/parse-config.js /app/docker/
COPY docker/run-oauth-migrations.js /app/docker/
COPY docker/create-admin-user.js /app/docker/
COPY docker/n8n-mcp /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/n8n-mcp \
    /app/docker/run-oauth-migrations.js /app/docker/create-admin-user.js

# Add container labels
LABEL org.opencontainers.image.source="https://github.com/czlonkowski/n8n-mcp"
LABEL org.opencontainers.image.description="n8n MCP Server - Runtime Only"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="n8n-mcp"

# Create non-root user with unpredictable UID/GID
# Using a hash of the build time to generate unpredictable IDs
RUN BUILD_HASH=$(date +%s | sha256sum | head -c 8) && \
    UID=$((10000 + 0x${BUILD_HASH} % 50000)) && \
    GID=$((10000 + 0x${BUILD_HASH} % 50000)) && \
    addgroup -g ${GID} -S nodejs && \
    adduser -S nodejs -u ${UID} -G nodejs && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Set Docker environment flag
ENV IS_DOCKER=true

# Telemetry: Anonymous usage statistics are ENABLED by default
# To opt-out, uncomment the following line:
# ENV N8N_MCP_TELEMETRY_DISABLED=true

# Expose HTTP port (default 3000, configurable via PORT environment variable at runtime)
EXPOSE 3000

# Set stop signal to SIGTERM (default, but explicit is better)
STOPSIGNAL SIGTERM

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c 'curl -f http://127.0.0.1:${PORT:-3000}/health || exit 1'

# Optimized entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/mcp/index.js"]
