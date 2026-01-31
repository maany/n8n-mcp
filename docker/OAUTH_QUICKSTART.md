# OAuth Quick Start Guide (Docker)

Get OAuth 2.1 authentication running in 2 minutes with Docker.

## Prerequisites

- Docker installed
- 2 minutes of your time

## Quick Start

### 1. Generate Secrets

```bash
# Generate random secrets
export BETTER_AUTH_SECRET=$(openssl rand -base64 32)
export AUTH_TOKEN=$(openssl rand -base64 32)
export OAUTH_ADMIN_PASSWORD="SecurePassword123!"
```

### 2. Run Container

```bash
docker run -d \
  --name n8n-mcp-oauth \
  -p 3000:3000 \
  -e ENABLE_OAUTH=true \
  -e BETTER_AUTH_SECRET="$BETTER_AUTH_SECRET" \
  -e BETTER_AUTH_URL=http://localhost:3000 \
  -e AUTH_TOKEN="$AUTH_TOKEN" \
  -e OAUTH_ADMIN_EMAIL=admin@example.com \
  -e OAUTH_ADMIN_PASSWORD="$OAUTH_ADMIN_PASSWORD" \
  -v n8n-mcp-data:/app/data \
  n8n-mcp:latest
```

### 3. Verify Startup

```bash
# Watch container logs
docker logs -f n8n-mcp-oauth

# Should see:
# ✓ OAuth database migrations completed successfully
# ✓ Admin user created successfully: admin@example.com
# Server listening on http://0.0.0.0:3000
```

### 4. Test OAuth Flow

#### Register an OAuth Client

```bash
curl -X POST http://localhost:3000/api/auth/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:8080/callback"],
    "token_endpoint_auth_method": "none"
  }'
```

Save the `client_id` from the response.

#### Start Authorization Flow

Open in your browser:
```
http://localhost:3000/api/auth/oauth2/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20mcp:read&state=test-state&code_challenge=CHALLENGE&code_challenge_method=S256
```

1. **Sign In**: Use `admin@example.com` / `SecurePassword123!`
2. **Approve**: Click "Allow Access"
3. **Get Code**: Copy authorization code from callback URL

#### Exchange Code for Token

```bash
curl -X POST http://localhost:3000/api/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "code_verifier=YOUR_CODE_VERIFIER" \
  -d "client_id=YOUR_CLIENT_ID"
```

#### Access MCP with OAuth Token

```bash
# Initialize session
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}},"id":1}'

# List MCP tools
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
```

## What Just Happened?

1. **Container Started** → OAuth migrations ran automatically
2. **Admin User Created** → Ready to sign in immediately
3. **OAuth Endpoints Active** → Full OAuth 2.1 provider running
4. **MCP Protected** → Access controlled via OAuth tokens

## Using Docker Compose

### Create `.env` File

```bash
cat > .env <<EOF
BETTER_AUTH_SECRET=$(openssl rand -base64 32)
AUTH_TOKEN=$(openssl rand -base64 32)
OAUTH_ADMIN_EMAIL=admin@example.com
OAUTH_ADMIN_PASSWORD=SecurePassword123!
EOF
```

### Use Example Compose File

```bash
# Copy example
cp docker/docker-compose.oauth.example.yml docker-compose.yml

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENABLE_OAUTH` | Yes | `false` | Enable OAuth 2.1 provider |
| `BETTER_AUTH_SECRET` | Yes | - | Secret for signing tokens (32+ bytes) |
| `BETTER_AUTH_URL` | Yes | - | Public server URL |
| `AUTH_TOKEN` | Yes | - | Admin API token (legacy) |
| `OAUTH_ADMIN_EMAIL` | No | - | Auto-create admin user with this email |
| `OAUTH_ADMIN_PASSWORD` | No | - | Password for admin user (min 8 chars) |
| `OAUTH_ADMIN_NAME` | No | `Admin User` | Display name for admin user |

## Troubleshooting

### Admin User Not Created

**Check logs:**
```bash
docker logs n8n-mcp-oauth | grep -i admin
```

**Common issues:**
- `OAUTH_ADMIN_PASSWORD` too short (must be ≥8 characters)
- Invalid email format
- User already exists (this is OK, not an error)

### OAuth Endpoints Return 404

**Verify OAuth is enabled:**
```bash
docker exec n8n-mcp-oauth env | grep ENABLE_OAUTH
# Should show: ENABLE_OAUTH=true
```

**Check server started:**
```bash
curl http://localhost:3000/health
```

### Migrations Failed

**Check data directory permissions:**
```bash
docker exec n8n-mcp-oauth ls -ld /app/data
```

**Check disk space:**
```bash
docker exec n8n-mcp-oauth df -h /app/data
```

## Security Best Practices

### Production Deployment

**Use Docker Secrets:**

```yaml
# docker-compose.yml
services:
  n8n-mcp:
    environment:
      - BETTER_AUTH_SECRET_FILE=/run/secrets/auth_secret
      - OAUTH_ADMIN_PASSWORD_FILE=/run/secrets/admin_password
    secrets:
      - auth_secret
      - admin_password

secrets:
  auth_secret:
    external: true
  admin_password:
    external: true
```

**Create secrets:**
```bash
echo "$(openssl rand -base64 32)" | docker secret create auth_secret -
echo "YourSecurePassword" | docker secret create admin_password -
```

### HTTPS in Production

**Update BETTER_AUTH_URL:**
```bash
BETTER_AUTH_URL=https://n8n-mcp.yourdomain.com
```

**Use reverse proxy:**
```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl

  n8n-mcp:
    expose:
      - "3000"
```

## Next Steps

- **Add More Users**: Call `/api/admin/users` endpoint
- **Configure MCP Client**: Use OAuth tokens in your MCP client
- **Enable Multi-Tenant**: Set `ENABLE_MULTI_TENANT=true`
- **Setup Monitoring**: Check `/health` endpoint regularly

## Resources

- [OAuth Implementation Guide](../OAUTH_IMPLEMENTATION.md)
- [Database Strategy](./DATABASE_STRATEGY.md)
- [Docker Compose Example](./docker-compose.oauth.example.yml)
- [Better Auth Documentation](https://www.better-auth.com/docs)
