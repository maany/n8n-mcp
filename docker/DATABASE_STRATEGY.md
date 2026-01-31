# Docker Database Strategy

## Overview

The n8n-mcp Docker image handles two databases with different initialization strategies:

1. **nodes.db** - Static reference data (build-time)
2. **auth.db** - User data with migrations (runtime)

## Database #1: nodes.db (Build-Time)

### Purpose
Contains n8n node documentation extracted from installed n8n packages.

### Strategy: Build During Image Creation

**Why Build-Time?**
- Static data derived from n8n packages (~70MB)
- Same for all users
- Slow to generate (~2 minutes)
- Building at runtime would delay every container startup

**Implementation:**
```dockerfile
# Stage 2: Database Builder
FROM node:22-alpine AS db-builder
WORKDIR /app

# Install full n8n packages
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Build nodes.db
RUN mkdir -p ./data && \
    node dist/scripts/rebuild.js

# Stage 3: Runtime
FROM node:22-alpine AS runtime
# Copy pre-built database
COPY --from=db-builder /app/data/nodes.db ./data/nodes.db
```

**Benefits:**
- ✅ Instant container startup (no rebuild delay)
- ✅ Consistent data across all containers
- ✅ Smaller runtime image (no n8n packages)
- ✅ Faster scaling (no per-container DB build)

**Trade-offs:**
- ❌ Larger image size (+70MB)
- ❌ Rebuild image when n8n updates

**Fallback:**
If `data/nodes.db` is missing at runtime (e.g., mounted volume), the entrypoint script will rebuild it automatically.

## Database #2: auth.db (Runtime)

### Purpose
OAuth 2.1 provider database containing:
- User accounts and passwords
- OAuth clients and tokens
- Sessions and consent records

### Strategy: Migrations at Container Startup

**Why Runtime?**
- User-specific data (different per deployment)
- Requires persistent storage (volume)
- Schema evolves (migrations needed)
- Security-sensitive data

**Implementation:**

1. **Migration Script:** `docker/run-oauth-migrations.js`
   ```javascript
   const { getMigrations } = require('better-auth/db');
   const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(authConfig);
   await runMigrations();
   ```

2. **Entrypoint Hook:** `docker/docker-entrypoint.sh`
   ```bash
   if [ "$ENABLE_OAUTH" = "true" ]; then
     node docker/run-oauth-migrations.js
   fi
   ```

**Benefits:**
- ✅ Follows database migration best practices
- ✅ Works with persistent volumes
- ✅ Schema can evolve independently
- ✅ No sensitive data in image

**Trade-offs:**
- ❌ Small startup delay (~100ms for migrations)
- ❌ Requires write access to data directory

**Migration Process:**
```
Container Start
  → Check ENABLE_OAUTH=true
  → Ensure /app/data exists
  → Run getMigrations()
    - Create tables if needed (first run)
    - Add columns if schema changed (upgrades)
  → Create Admin User (if OAUTH_ADMIN_EMAIL provided)
    - Check if user already exists
    - Create user with provided credentials
    - Skip if user exists
  → Start application
```

### Automatic Admin User Creation

**Purpose:** Simplify first-time OAuth setup in Docker deployments

**Configuration:**
```bash
OAUTH_ADMIN_EMAIL=admin@example.com
OAUTH_ADMIN_PASSWORD=SecurePassword123!
OAUTH_ADMIN_NAME=Admin User  # Optional
```

**Implementation:** `docker/create-admin-user.js`
- Runs after migrations complete
- Uses better-auth `signUpEmail()` API
- Idempotent (safe to run multiple times)
- Validates email format and password strength
- Fails container startup on errors

**Security Best Practices:**
- Password must be ≥8 characters
- Email must be valid format
- Use Docker secrets in production (not plain environment variables)

**Production Setup Example:**
```yaml
# docker-compose.yml
services:
  n8n-mcp:
    environment:
      - ENABLE_OAUTH=true
      - BETTER_AUTH_SECRET_FILE=/run/secrets/auth_secret
    secrets:
      - auth_secret
      - admin_email
      - admin_password

secrets:
  auth_secret:
    external: true
  admin_email:
    external: true
  admin_password:
    external: true
```

## Volume Mounting Strategy

### Production Deployment

**Recommended:**
```yaml
volumes:
  - oauth-data:/app/data  # Persistent volume for auth.db
```

**Why:**
- nodes.db comes from image (no volume needed)
- auth.db persists across container restarts
- User data survives deployments

### Development Override

**Optional:**
```yaml
volumes:
  - ./local-data:/app/data  # Override both databases
```

**Use Cases:**
- Testing with custom n8n versions
- Development with local database
- Data inspection/debugging

## Migration Safety

### Race Condition Protection

The entrypoint uses file locking for nodes.db rebuild:
```bash
flock -x 200
  if [ ! -f "$DB_PATH" ]; then
    node dist/scripts/rebuild.js
  fi
) 200>"$DB_DIR/.db.lock"
```

For auth.db, better-auth's `getMigrations()` is idempotent:
- Multiple containers can run migrations safely
- Already-applied migrations are skipped
- Schema changes are atomic

### Rollback Strategy

**nodes.db:**
- Roll back to previous image version
- Database is embedded in image

**auth.db:**
- Requires better-auth schema version compatibility
- Test migrations in staging first
- Backup auth.db before major updates

## Performance Characteristics

| Operation | Time | When |
|-----------|------|------|
| nodes.db build (Docker build) | ~2 min | Once per image |
| nodes.db rebuild (runtime fallback) | ~2 min | Only if missing |
| auth.db migrations (first run) | ~100ms | First container start |
| auth.db migrations (subsequent) | ~20ms | Each container start |
| Container startup (warm) | <1s | With both DBs ready |

## Security Considerations

### auth.db Protection

**Volume Permissions:**
```dockerfile
RUN adduser -S nodejs -u ${UID}
USER nodejs
```

**Runtime Checks:**
```bash
if [ "$(id -u)" = "0" ] && [ -f "/app/data/auth.db" ]; then
  chown nodejs:nodejs /app/data/auth.db
fi
```

**Best Practices:**
- Never commit auth.db to git (contains passwords/tokens)
- Use volume encryption in production
- Restrict volume access to application containers
- Regular backups with encryption

### nodes.db Security

- Read-only database (no user data)
- Can be safely cached in CI/CD
- No encryption needed (public documentation)

## Troubleshooting

### nodes.db Missing in Container

**Symptom:** Container rebuilds database on every start

**Cause:** Image build failed at db-builder stage

**Solution:**
```bash
# Check build logs for stage 2
docker build --progress=plain .

# Verify database in image
docker run --rm image-name ls -lh /app/data/nodes.db
```

### auth.db Migration Failures

**Symptom:** "OAuth migrations failed" warning

**Common Causes:**
1. Volume not writable
2. Insufficient disk space
3. better-auth version mismatch

**Solution:**
```bash
# Check volume permissions
docker exec container-id ls -ld /app/data

# Check disk space
docker exec container-id df -h /app/data

# View migration logs
docker logs container-id | grep -A 10 "OAuth migrations"
```

### Permission Denied Errors

**Symptom:** Cannot write to /app/data

**Solution:**
```bash
# Fix volume ownership
docker run --rm -v oauth-data:/data alpine chown -R 10000:10000 /data
```

## Summary

| Database | Build Strategy | Size | Persistence | Updates |
|----------|---------------|------|-------------|---------|
| **nodes.db** | Build-time (image) | 70MB | In image | Rebuild image |
| **auth.db** | Runtime (migrations) | <1MB | Volume | Auto-migrate |

This hybrid approach optimizes for:
- Fast container startup (nodes.db pre-built)
- Data persistence (auth.db on volume)
- Security (auth.db never in image)
- Flexibility (both can be overridden)

---

**Sources:**
- [Better Auth Database Documentation](https://www.better-auth.com/docs/concepts/database)
- [Better Auth CLI Documentation](https://www.better-auth.com/docs/concepts/cli)
