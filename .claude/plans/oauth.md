# Better-Auth OAuth Provider Integration Plan

## Overview
Integrate better-auth OAuth 2.1 provider into n8n-mcp HTTP server to enable MCP clients to authenticate via OAuth while maintaining backward compatibility with Bearer token authentication.

## User Requirements
- **User creation**: Admin-only API endpoint (no public sign-up page)
- **OAuth mode**: Feature flag (`ENABLE_OAUTH`) for gradual rollout
- **Token audience**: Use server base URL (`BETTER_AUTH_URL`)
- **Database migration**: Not yet created - needs to be run

## Critical Files to Modify

1. **src/utils/auth.ts** - Configure better-auth with oauthProvider plugin
2. **src/http-server-single-session.ts** - Add OAuth routes and dual authentication
3. **src/public/sign-in.html** - Login page for OAuth flow
4. **src/public/consent.html** - Consent page for scope authorization
5. **.env.example** - Document new environment variables

## Implementation Steps

### Step 1: Database Migration Setup

**Prerequisites**:
```bash
npm install -D @better-auth/cli
```

**Add scripts to package.json**:
```json
"scripts": {
  "auth:migrate": "better-auth migrate",
  "auth:generate": "better-auth generate"
}
```

**Run migration** (creates OAuth tables):
```bash
npm run auth:migrate
```

**Expected tables created**:
- `oauthClient` - OAuth client registrations
- `oauthRefreshToken` - Refresh tokens
- `oauthAccessToken` - Access token references (if using opaque tokens)
- `oauthConsent` - User consent records
- `user` - User accounts (if not exists)
- `session` - User sessions (if not exists)

### Step 2: Update Better-Auth Configuration

**File**: `src/utils/auth.ts`

**Changes**:

1. Import OAuth provider plugin:
```typescript
import { oauthProvider } from "@better-auth/oauth-provider";
import { toNodeHandler } from "better-auth/node";
```

2. Add configuration:
```typescript
export const auth = betterAuth({
  database: new Database(path.join(process.cwd(), 'data', 'auth.db')),

  // Required security settings
  secret: process.env.BETTER_AUTH_SECRET || crypto.randomBytes(32).toString('hex'),
  baseURL: process.env.BETTER_AUTH_URL || 'http://localhost:3000',

  plugins: [
    jwt(),
    mcp(),
    oauthProvider({
      // Page routes (relative to baseURL)
      loginPage: "/sign-in",
      consentPage: "/consent",

      // MCP-specific: Allow clients to self-register
      allowDynamicClientRegistration: true,
      allowUnauthenticatedClientRegistration: true,

      // Supported scopes
      scopes: [
        "openid",
        "profile",
        "email",
        "offline_access",
        "mcp:read",
        "mcp:write"
      ],

      // Token expiration
      accessTokenExpiresIn: 3600, // 1 hour
      refreshTokenExpiresIn: 2592000, // 30 days

      // Audience validation (use server base URL per user requirement)
      validAudiences: [
        process.env.BETTER_AUTH_URL || "http://localhost:3000"
      ],

      // Security: Hash client secrets
      storeClientSecret: "hashed",

      // Disable JWT plugin would use opaque tokens - keep false for stateless verification
      disableJwtPlugin: false
    })
  ]
}) as ReturnType<typeof betterAuth>

// Export Express-compatible handler
export const authHandler = toNodeHandler(auth);
```

3. Add helper function for OAuth token verification:
```typescript
export async function verifyOAuthToken(token: string): Promise<{
  valid: boolean;
  userId?: string;
  scopes?: string[];
}> {
  try {
    const payload = await auth.api.verifyAccessToken({
      token,
      options: {
        issuer: process.env.BETTER_AUTH_URL || 'http://localhost:3000',
        audience: process.env.BETTER_AUTH_URL || 'http://localhost:3000'
      }
    });

    if (payload && payload.active) {
      return {
        valid: true,
        userId: payload.sub,
        scopes: payload.scope?.split(' ')
      };
    }
  } catch (error) {
    // Token verification failed
  }

  return { valid: false };
}
```

### Step 3: HTTP Server Integration

**File**: `src/http-server-single-session.ts`

**Location**: In the `start()` method, after middleware setup (around line 836)

**Changes**:

1. Import auth utilities at top of file:
```typescript
import { authHandler, verifyOAuthToken } from './utils/auth';
import {
  oauthProviderOpenIdConfigMetadata,
  oauthProviderAuthServerMetadata
} from '@better-auth/oauth-provider';
import { auth } from './utils/auth';
import path from 'path';
import { fileURLToPath } from 'url';
```

2. Add static file serving (after middleware, before routes):
```typescript
// Serve OAuth UI pages from public directory
if (process.env.ENABLE_OAUTH === 'true') {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const publicPath = path.join(__dirname, 'public');
  app.use(express.static(publicPath));
  logger.info('OAuth pages enabled at /sign-in and /consent');
}
```

3. Mount better-auth handler (before root endpoint):
```typescript
// Mount Better-Auth OAuth provider (if enabled)
if (process.env.ENABLE_OAUTH === 'true') {
  app.all('/api/auth/*', authHandler);
  logger.info('Better-Auth OAuth provider mounted at /api/auth/*');
}
```

4. Add well-known metadata endpoints (after auth handler):
```typescript
if (process.env.ENABLE_OAUTH === 'true') {
  // OpenID Configuration Discovery
  app.get('/.well-known/openid-configuration', (req, res) => {
    try {
      const metadata = oauthProviderOpenIdConfigMetadata(auth);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json(metadata);
    } catch (error) {
      logger.error('Error generating OpenID config', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // OAuth Authorization Server Metadata
  app.get('/.well-known/oauth-authorization-server', (req, res) => {
    try {
      const metadata = oauthProviderAuthServerMetadata(auth);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json(metadata);
    } catch (error) {
      logger.error('Error generating OAuth metadata', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // MCP Protected Resource Metadata
  app.get('/.well-known/oauth-protected-resource', (req, res) => {
    try {
      const baseUrl = process.env.BETTER_AUTH_URL || `http://${req.get('host')}`;
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json({
        resource: baseUrl,
        authorization_servers: [baseUrl],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp:read", "mcp:write", "openid", "profile", "email"],
        resource_types_supported: ["mcp_server"]
      });
    } catch (error) {
      logger.error('Error generating resource metadata', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
}
```

5. Add admin user creation endpoint (before root endpoint):
```typescript
// Admin endpoint to create users (protected by AUTH_TOKEN)
if (process.env.ENABLE_OAUTH === 'true') {
  app.post('/api/admin/users', jsonParser, async (req, res) => {
    // Verify admin auth token
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.slice(7).trim();
    const isValidToken = this.authToken &&
      AuthManager.timingSafeCompare(token, this.authToken);

    if (!isValidToken) {
      logger.warn('Admin user creation failed: Invalid token', { ip: req.ip });
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Create user via better-auth
    try {
      const { email, password, name } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
      }

      const user = await auth.api.signUpEmail({
        body: { email, password, name }
      });

      logger.info('Admin created user', { email, userId: user.data?.user?.id });

      res.json({
        success: true,
        user: {
          id: user.data?.user?.id,
          email: user.data?.user?.email,
          name: user.data?.user?.name
        }
      });
    } catch (error: any) {
      logger.error('User creation failed', error);
      res.status(400).json({
        error: error.message || 'User creation failed'
      });
    }
  });
}
```

6. Update `/mcp` POST endpoint authentication (around line 1185):
```typescript
// Dual authentication: try OAuth first, fallback to bearer token
const authHeader = req.headers.authorization;

if (!authHeader) {
  logger.warn('Authentication failed: Missing Authorization header', {
    ip: req.ip,
    reason: 'no_auth_header'
  });
  res.status(401).json({
    jsonrpc: '2.0',
    error: { code: -32001, message: 'Unauthorized' },
    id: null
  });
  return;
}

let authenticated = false;
let authMethod = 'none';

// Try OAuth token verification if enabled
if (process.env.ENABLE_OAUTH === 'true' && authHeader.startsWith('Bearer ')) {
  const token = authHeader.slice(7).trim();
  const oauthResult = await verifyOAuthToken(token);

  if (oauthResult.valid) {
    authenticated = true;
    authMethod = 'oauth';
    logger.info('OAuth authentication successful', {
      userId: oauthResult.userId,
      scopes: oauthResult.scopes
    });
  }
}

// Fallback to legacy bearer token
if (!authenticated) {
  if (!authHeader.startsWith('Bearer ')) {
    logger.warn('Authentication failed: Invalid format', {
      ip: req.ip,
      reason: 'invalid_auth_format'
    });
    res.status(401).json({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Unauthorized' },
      id: null
    });
    return;
  }

  const token = authHeader.slice(7).trim();
  const isValidToken = this.authToken &&
    AuthManager.timingSafeCompare(token, this.authToken);

  if (!isValidToken) {
    logger.warn('Authentication failed: Invalid token', {
      ip: req.ip,
      reason: 'invalid_token'
    });
    res.status(401).json({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Unauthorized' },
      id: null
    });
    return;
  }

  authenticated = true;
  authMethod = 'bearer_token';
}

logger.debug('Request authenticated', { method: authMethod });
```

7. Update CORS headers to support OAuth (around line 817):
```typescript
res.setHeader('Access-Control-Allow-Headers',
  'Content-Type, Authorization, Accept, Mcp-Session-Id, X-Requested-With');
```

### Step 4: Create OAuth UI Pages

**Create directory**: `src/public/`

#### File: `src/public/sign-in.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - n8n MCP OAuth</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Sign In to n8n MCP</h1>
      <p class="subtitle">OAuth Authorization Request</p>
    </div>

    <form id="login-form" class="auth-form">
      <div class="form-group">
        <label for="email">Email Address</label>
        <input
          type="email"
          id="email"
          name="email"
          required
          autofocus
          autocomplete="email"
          placeholder="your@email.com"
        >
      </div>

      <div class="form-group">
        <label for="password">Password</label>
        <input
          type="password"
          id="password"
          name="password"
          required
          autocomplete="current-password"
        >
      </div>

      <button type="submit" class="btn-primary">Sign In</button>

      <div id="error-message" class="error" role="alert"></div>
    </form>
  </div>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const oauthQuery = urlParams.get('oauth_query');

    document.getElementById('login-form').addEventListener('submit', async (e) => {
      e.preventDefault();

      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const errorEl = document.getElementById('error-message');

      errorEl.textContent = '';

      try {
        const response = await fetch('/api/auth/sign-in/email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });

        if (response.ok) {
          // Redirect back to OAuth flow
          if (oauthQuery) {
            const redirectUrl = new URL('/api/auth/oauth2/authorize', window.location.origin);
            redirectUrl.searchParams.set('oauth_query', oauthQuery);
            window.location.href = redirectUrl.toString();
          } else {
            window.location.href = '/';
          }
        } else {
          const error = await response.json();
          errorEl.textContent = error.message || 'Invalid email or password';
        }
      } catch (error) {
        errorEl.textContent = 'Network error. Please try again.';
      }
    });
  </script>
</body>
</html>
```

#### File: `src/public/consent.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorization Request - n8n MCP</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Authorization Request</h1>
    </div>

    <div id="client-info" class="client-info">
      <p class="client-name"><strong id="client-name-text"></strong> wants to access your account</p>
      <p class="redirect-uri">Will redirect to: <code id="redirect-uri-text"></code></p>
    </div>

    <div class="scopes">
      <h2>Requested Permissions</h2>
      <ul id="scope-list" class="scope-list"></ul>
    </div>

    <div class="actions">
      <button id="allow-btn" class="btn-primary">Allow Access</button>
      <button id="deny-btn" class="btn-secondary">Deny</button>
    </div>

    <div id="error-message" class="error" role="alert"></div>
  </div>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const oauthQuery = urlParams.get('oauth_query');
    const clientId = urlParams.get('client_id');
    const scope = urlParams.get('scope');
    const redirectUri = urlParams.get('redirect_uri');

    // Scope descriptions for user-friendly display
    const scopeDescriptions = {
      'openid': 'Verify your identity',
      'profile': 'Access your profile information',
      'email': 'Access your email address',
      'offline_access': 'Maintain access when you are offline',
      'mcp:read': 'Read n8n node documentation and workflow data',
      'mcp:write': 'Create and modify n8n workflows'
    };

    // Display consent details
    function displayConsent() {
      document.getElementById('client-name-text').textContent = clientId || 'Unknown Application';
      document.getElementById('redirect-uri-text').textContent = redirectUri || 'Unknown';

      const scopes = scope ? scope.split(' ') : [];
      const scopeList = document.getElementById('scope-list');
      scopeList.innerHTML = '';

      scopes.forEach(s => {
        const li = document.createElement('li');
        const description = scopeDescriptions[s] || s;
        li.innerHTML = `<strong>${s}</strong>: ${description}`;
        scopeList.appendChild(li);
      });
    }

    document.getElementById('allow-btn').addEventListener('click', async () => {
      await submitConsent(true);
    });

    document.getElementById('deny-btn').addEventListener('click', async () => {
      await submitConsent(false);
    });

    async function submitConsent(approved) {
      const errorEl = document.getElementById('error-message');
      errorEl.textContent = '';

      try {
        const response = await fetch('/api/auth/oauth2/consent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            oauth_query: oauthQuery,
            approved,
            scope: approved ? scope : undefined
          })
        });

        if (response.ok) {
          const result = await response.json();
          // Redirect will be handled by better-auth
          if (result.redirect_uri) {
            window.location.href = result.redirect_uri;
          }
        } else {
          const error = await response.json();
          errorEl.textContent = error.message || 'Authorization failed';
        }
      } catch (error) {
        errorEl.textContent = 'Network error. Please try again.';
      }
    }

    // Initialize
    if (!oauthQuery) {
      document.getElementById('error-message').textContent = 'Invalid authorization request';
      document.getElementById('allow-btn').disabled = true;
    } else {
      displayConsent();
    }
  </script>
</body>
</html>
```

#### File: `src/public/styles.css`

```css
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue', sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.container {
  background: white;
  border-radius: 12px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
  max-width: 480px;
  width: 100%;
  padding: 40px;
}

.header {
  text-align: center;
  margin-bottom: 30px;
}

h1 {
  color: #1a1a1a;
  font-size: 28px;
  font-weight: 600;
  margin-bottom: 8px;
}

.subtitle {
  color: #666;
  font-size: 14px;
}

.auth-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

label {
  color: #333;
  font-size: 14px;
  font-weight: 500;
}

input {
  padding: 12px 16px;
  border: 1px solid #ddd;
  border-radius: 8px;
  font-size: 15px;
  transition: border-color 0.2s;
}

input:focus {
  outline: none;
  border-color: #667eea;
  box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.btn-primary,
.btn-secondary {
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 15px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: #667eea;
  color: white;
}

.btn-primary:hover {
  background: #5568d3;
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
  background: #f0f0f0;
  color: #666;
}

.btn-secondary:hover {
  background: #e0e0e0;
}

.error {
  color: #dc3545;
  font-size: 14px;
  padding: 12px;
  background: #f8d7da;
  border: 1px solid #f5c6cb;
  border-radius: 6px;
  display: none;
}

.error:not(:empty) {
  display: block;
}

.client-info {
  background: #f8f9fa;
  padding: 20px;
  border-radius: 8px;
  margin-bottom: 24px;
}

.client-name {
  font-size: 16px;
  margin-bottom: 8px;
  color: #1a1a1a;
}

.redirect-uri {
  font-size: 13px;
  color: #666;
}

.redirect-uri code {
  background: #e9ecef;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: 12px;
}

.scopes {
  margin-bottom: 24px;
}

h2 {
  font-size: 18px;
  color: #333;
  margin-bottom: 12px;
}

.scope-list {
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.scope-list li {
  padding: 12px;
  background: #f8f9fa;
  border-radius: 6px;
  font-size: 14px;
  color: #555;
}

.scope-list strong {
  color: #667eea;
  font-weight: 600;
}

.actions {
  display: flex;
  gap: 12px;
  margin-top: 24px;
}

.actions button {
  flex: 1;
}

@media (max-width: 480px) {
  .container {
    padding: 24px;
  }

  h1 {
    font-size: 24px;
  }

  .actions {
    flex-direction: column-reverse;
  }
}
```

### Step 5: Update Build Configuration

**File**: `package.json`

Add build step to copy public files:

```json
"scripts": {
  "build": "tsc -p tsconfig.build.json && npm run copy:public",
  "copy:public": "mkdir -p dist/public && cp -r src/public/* dist/public/",
  "auth:migrate": "better-auth migrate"
}
```

Or using cross-platform solution:

```bash
npm install -D cpy-cli
```

```json
"scripts": {
  "build": "tsc -p tsconfig.build.json && npm run copy:public",
  "copy:public": "cpy 'src/public/**' 'dist/public' --parents",
  "auth:migrate": "better-auth migrate"
}
```

### Step 6: Environment Configuration

**File**: `.env.example`

Add OAuth configuration section:

```bash
# =========================
# BETTER AUTH OAUTH PROVIDER
# =========================

# Enable OAuth 2.1 authentication (default: false)
# When enabled, OAuth provider endpoints are exposed alongside bearer token auth
ENABLE_OAUTH=false

# Better Auth Secret (REQUIRED when ENABLE_OAUTH=true)
# Generate with: openssl rand -base64 32
# Used to sign JWT tokens and encrypt sensitive data
BETTER_AUTH_SECRET=

# Better Auth Base URL (REQUIRED when ENABLE_OAUTH=true)
# Must match the public URL where this server is accessible
# Used for OAuth redirects and token audience validation
# Examples:
#   - Development: http://localhost:3000
#   - Production: https://n8n-mcp.yourdomain.com
BETTER_AUTH_URL=http://localhost:3000
```

**Update existing auth section**:
```bash
# Authentication token for HTTP mode (REQUIRED unless using OAuth)
# Generate with: openssl rand -base64 32
# Note: When ENABLE_OAUTH=true, this token is still used for:
#   - Admin API endpoints (/api/admin/users)
#   - Backward compatibility with existing clients
AUTH_TOKEN=your-secure-token-here
```

### Step 7: Testing & Verification

**Manual Testing Steps**:

1. **Database migration**:
```bash
npm run auth:migrate
# Verify tables created in data/auth.db
```

2. **Build project**:
```bash
npm run build
# Verify dist/public/ directory exists with HTML/CSS files
```

3. **Create admin user**:
```bash
curl -X POST http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"secure-password","name":"Admin User"}'
```

4. **Register OAuth client** (dynamic registration):
```bash
curl -X POST http://localhost:3000/api/auth/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test MCP Client",
    "redirect_uris": ["http://localhost:8080/callback"],
    "token_endpoint_auth_method": "none"
  }'
```

5. **Test authorization flow**:
- Open browser: `http://localhost:3000/api/auth/oauth2/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid mcp:read&state=random-state&code_challenge=CHALLENGE&code_challenge_method=S256`
- Should redirect to `/sign-in` with `oauth_query` parameter
- Login with created user
- Should redirect to `/consent`
- Approve scopes
- Should redirect to callback URL with authorization code

6. **Exchange code for token**:
```bash
curl -X POST http://localhost:3000/api/auth/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:8080/callback&code_verifier=VERIFIER&client_id=CLIENT_ID"
```

7. **Test MCP endpoint with OAuth token**:
```bash
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer OAUTH_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

8. **Verify backward compatibility** (bearer token still works):
```bash
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

9. **Test well-known endpoints**:
```bash
curl http://localhost:3000/.well-known/openid-configuration
curl http://localhost:3000/.well-known/oauth-authorization-server
curl http://localhost:3000/.well-known/oauth-protected-resource
```

**Automated Tests** (create later):
- Unit tests for `verifyOAuthToken()` function
- Integration tests for complete OAuth flow
- Tests for dual authentication logic
- Tests for admin user creation endpoint

### Step 8: Documentation Updates

**Files to update**:

1. **README.md** - Add OAuth setup section:
   - Overview of OAuth support
   - Configuration instructions
   - User creation steps
   - Client registration examples
   - MCP client integration guide

2. **Create docs/OAUTH_SETUP.md**:
   - Detailed OAuth provider guide
   - Environment variable reference
   - Client registration workflows
   - Troubleshooting common issues

3. **Update API documentation** with new endpoints:
   - `/api/auth/*` - OAuth provider endpoints
   - `/api/admin/users` - User management
   - `/.well-known/*` - Discovery endpoints

## Security Considerations

1. **PKCE enforcement**: Automatic via better-auth (S256 required, plain disabled)
2. **State parameter**: Automatic CSRF protection via better-auth
3. **Token storage**: Client secrets hashed, refresh tokens hashed, access tokens as JWT
4. **HTTPS requirement**: OAuth should only be used over HTTPS in production
5. **Rate limiting**: Applied to OAuth endpoints (same as existing /mcp endpoint)
6. **Admin endpoint protection**: Uses existing AUTH_TOKEN for admin operations
7. **Secret management**: BETTER_AUTH_SECRET must be set and kept secure

## Backward Compatibility

- Existing bearer token authentication continues to work
- OAuth is opt-in via `ENABLE_OAUTH` environment variable
- Dual authentication logic tries OAuth first, falls back to bearer token
- No breaking changes for existing deployments
- Migration path: Users can test OAuth while keeping bearer tokens active

## Success Criteria

✅ Database migration creates OAuth tables successfully
✅ Admin can create users via API endpoint
✅ OAuth authorization flow completes (login → consent → code → token)
✅ MCP clients can authenticate with OAuth tokens
✅ Bearer token authentication still works (backward compatibility)
✅ Well-known endpoints return correct metadata
✅ MCP clients can discover OAuth via `.well-known/oauth-protected-resource`
✅ Dynamic client registration works for public clients
✅ All security requirements met (PKCE, state, token hashing)
✅ Feature flag (`ENABLE_OAUTH`) allows gradual rollout

## Risks & Mitigation

**Low Risk**:
- Database migration is additive only (creates new tables)
- HTML pages are isolated static files
- Feature flag allows testing without affecting production

**Medium Risk**:
- HTTP server routing changes require thorough testing
- Authentication logic must maintain backward compatibility
- Mitigation: Comprehensive manual testing + dual auth pattern

**No Breaking Changes**: Implementation is fully backward compatible when `ENABLE_OAUTH=false` (default)
