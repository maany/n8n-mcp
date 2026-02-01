import crypto from 'crypto';
import path from 'path';
import { betterAuth } from "better-auth";
import Database from "better-sqlite3";
import { jwtVerify, createRemoteJWKSet } from 'jose';

import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { toNodeHandler } from "better-auth/node";

// Build valid audiences and protected resources based on BETTER_AUTH_URL
const baseAuthUrl = process.env.BETTER_AUTH_URL || 'http://localhost:3000';
const validAudiences = [baseAuthUrl, `${baseAuthUrl}/mcp`];
const protectedResources = [baseAuthUrl, `${baseAuthUrl}/mcp`];

// Only configure OAuth when enabled
const authConfig = process.env.ENABLE_OAUTH === 'true' ? {
    database: new Database(path.join(process.cwd(), 'data', 'auth.db')),
    secret: process.env.BETTER_AUTH_SECRET || crypto.randomBytes(32).toString('hex'),
    baseURL: process.env.BETTER_AUTH_URL || 'http://localhost:3000',

    // Enable email/password authentication
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: false
    },

    plugins: [
        jwt(),
        oauthProvider({
            loginPage: "/sign-in",
            consentPage: "/consent",
            allowDynamicClientRegistration: true,
            allowUnauthenticatedClientRegistration: true,
            scopes: [
                "openid",
                "profile",
                "email",
                "offline_access",
                "mcp:read",
                "mcp:write"
            ],
            accessTokenExpiresIn: 3600,
            refreshTokenExpiresIn: 2592000,
            validAudiences,
            protectedResources,
            storeClientSecret: "hashed",
            disableJwtPlugin: false
        })
    ]
} : {
    database: new Database(path.join(process.cwd(), 'data', 'auth.db')),
    secret: process.env.BETTER_AUTH_SECRET || crypto.randomBytes(32).toString('hex'),
    baseURL: process.env.BETTER_AUTH_URL || 'http://localhost:3000',

    // Enable email/password authentication even when OAuth is disabled
    emailAndPassword: {
        enabled: true,
        requireEmailVerification: false
    }
};

export const auth = betterAuth(authConfig) as ReturnType<typeof betterAuth>;

// Export Express-compatible handler
export const authHandler = toNodeHandler(auth);

/**
 * Token verification result type
 */
type TokenVerificationResult = {
    valid: boolean;
    userId?: string;
    scopes?: string[];
};

/**
 * Verify OAuth access token using two-tier verification:
 * 1. Database lookup for opaque tokens (stored by better-auth)
 * 2. JWT signature verification for JWT tokens (ID tokens or JWT access tokens)
 *
 * Returns { valid: false } when OAuth is disabled
 *
 * Note: We query the database directly instead of using the introspection endpoint
 * because the endpoint requires client authentication, which public clients don't have.
 * Since we run both the auth server and resource server in the same process,
 * direct database access is more efficient and secure.
 */
export async function verifyOAuthToken(token: string): Promise<TokenVerificationResult> {
    if (process.env.ENABLE_OAUTH !== 'true') {
        return { valid: false };
    }

    // Tier 1: Try database lookup for opaque tokens
    const dbResult = await verifyOpaqueToken(token);
    if (dbResult.valid) {
        return dbResult;
    }

    // Tier 2: Try JWT verification as fallback
    const jwtResult = await verifyJwtToken(token);
    return jwtResult;
}

/**
 * Verify opaque access token by checking the database
 * Better-auth stores hashed tokens using SHA-256 with URL-safe base64 encoding
 */
async function verifyOpaqueToken(token: string): Promise<TokenVerificationResult> {
    try {
        // Hash the token to match the database storage
        const hashedToken = crypto.createHash('sha256')
            .update(token)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        // Query the oauthAccessToken table directly
        const dbPath = path.join(process.cwd(), 'data', 'auth.db');
        const db = new Database(dbPath, { readonly: true });

        const tokenRecord = db.prepare(`
            SELECT token, userId, scopes, expiresAt
            FROM oauthAccessToken
            WHERE token = ?
        `).get(hashedToken) as {
            token: string;
            userId: string;
            scopes: string;
            expiresAt: string;
        } | undefined;

        db.close();

        if (!tokenRecord) {
            return { valid: false };
        }

        // Check if token is expired (expiresAt is ISO date string)
        const expiresAt = new Date(tokenRecord.expiresAt).getTime();
        const now = Date.now();
        if (expiresAt < now) {
            return { valid: false };
        }

        // Parse scopes from JSON array format
        let scopes: string[] = [];
        try {
            scopes = JSON.parse(tokenRecord.scopes);
        } catch (e) {
            // If not JSON, try space-separated fallback
            scopes = tokenRecord.scopes ? tokenRecord.scopes.split(' ') : [];
        }

        return {
            valid: true,
            userId: tokenRecord.userId,
            scopes: scopes
        };
    } catch (error) {
        console.error('Opaque token verification failed:', error);
        return { valid: false };
    }
}

/**
 * Parse scope claim from JWT payload
 * Handles both space-separated strings and JSON arrays
 */
function parseScopes(scopeClaim: unknown): string[] {
    if (!scopeClaim) {
        return [];
    }

    if (Array.isArray(scopeClaim)) {
        return scopeClaim.filter((s): s is string => typeof s === 'string');
    }

    if (typeof scopeClaim === 'string') {
        return scopeClaim.split(' ').filter(s => s.length > 0);
    }

    return [];
}

/**
 * Verify JWT token by validating signature against JWKS
 * Supports both JWT access tokens and ID tokens from better-auth
 */
async function verifyJwtToken(token: string): Promise<TokenVerificationResult> {
    // Check if token looks like a JWT (3 dot-separated parts)
    const parts = token.split('.');
    if (parts.length !== 3) {
        return { valid: false };
    }

    try {
        // Fetch JWKS from better-auth endpoint
        const jwksUrl = new URL(`${baseAuthUrl}/api/auth/jwks`);
        const JWKS = createRemoteJWKSet(jwksUrl);

        // Better-auth uses /api/auth as the issuer path
        const issuer = `${baseAuthUrl}/api/auth`;

        // Valid audiences include the MCP endpoint and userinfo endpoint
        const audiences = [
            ...validAudiences,
            `${baseAuthUrl}/api/auth/oauth2/userinfo`
        ];

        // Verify signature, expiry, audience, and issuer
        const { payload } = await jwtVerify(token, JWKS, {
            audience: audiences,
            issuer: issuer
        });

        // Extract userId from sub claim
        if (!payload.sub) {
            console.error('JWT verification failed: missing sub claim');
            return { valid: false };
        }

        // Extract scopes from scope claim
        const scopes = parseScopes(payload.scope);

        return {
            valid: true,
            userId: payload.sub,
            scopes: scopes
        };
    } catch (error) {
        // Only log if debug-level logging is needed, as JWT failures are expected
        // when opaque tokens fail and fallback is attempted
        if (process.env.DEBUG_AUTH === 'true') {
            console.error('JWT token verification failed:', error);
        }
        return { valid: false };
    }
}


export class AuthManager {
  private validTokens: Set<string>;
  private tokenExpiry: Map<string, number>;

  constructor() {
    this.validTokens = new Set();
    this.tokenExpiry = new Map();
  }

  /**
   * Validate an authentication token
   */
  validateToken(token: string | undefined, expectedToken?: string): boolean {
    if (!expectedToken) {
      // No authentication required
      return true;
    }

    if (!token) {
      return false;
    }

    // SECURITY: Use timing-safe comparison for static token
    // See: https://github.com/czlonkowski/n8n-mcp/issues/265 (CRITICAL-02)
    if (AuthManager.timingSafeCompare(token, expectedToken)) {
      return true;
    }

    // Check dynamic tokens
    if (this.validTokens.has(token)) {
      const expiry = this.tokenExpiry.get(token);
      if (expiry && expiry > Date.now()) {
        return true;
      } else {
        // Token expired
        this.validTokens.delete(token);
        this.tokenExpiry.delete(token);
        return false;
      }
    }

    return false;
  }

  /**
   * Generate a new authentication token
   */
  generateToken(expiryHours: number = 24): string {
    const token = crypto.randomBytes(32).toString('hex');
    const expiryTime = Date.now() + (expiryHours * 60 * 60 * 1000);

    this.validTokens.add(token);
    this.tokenExpiry.set(token, expiryTime);

    // Clean up expired tokens
    this.cleanupExpiredTokens();

    return token;
  }

  /**
   * Revoke a token
   */
  revokeToken(token: string): void {
    this.validTokens.delete(token);
    this.tokenExpiry.delete(token);
  }

  /**
   * Clean up expired tokens
   */
  private cleanupExpiredTokens(): void {
    const now = Date.now();
    for (const [token, expiry] of this.tokenExpiry.entries()) {
      if (expiry <= now) {
        this.validTokens.delete(token);
        this.tokenExpiry.delete(token);
      }
    }
  }

  /**
   * Hash a password or token for secure storage
   */
  static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Compare a plain token with a hashed token
   */
  static compareTokens(plainToken: string, hashedToken: string): boolean {
    const hashedPlainToken = AuthManager.hashToken(plainToken);
    return crypto.timingSafeEqual(
      Buffer.from(hashedPlainToken),
      Buffer.from(hashedToken)
    );
  }

  /**
   * Compare two tokens using constant-time algorithm to prevent timing attacks
   *
   * @param plainToken - Token from request
   * @param expectedToken - Expected token value
   * @returns true if tokens match, false otherwise
   *
   * @security This uses crypto.timingSafeEqual to prevent timing attack vulnerabilities.
   * Never use === or !== for token comparison as it allows attackers to discover
   * tokens character-by-character through timing analysis.
   *
   * @example
   * const isValid = AuthManager.timingSafeCompare(requestToken, serverToken);
   * if (!isValid) {
   *   return res.status(401).json({ error: 'Unauthorized' });
   * }
   *
   * @see https://github.com/czlonkowski/n8n-mcp/issues/265 (CRITICAL-02)
   */
  static timingSafeCompare(plainToken: string, expectedToken: string): boolean {
    try {
      // Tokens must be non-empty
      if (!plainToken || !expectedToken) {
        return false;
      }

      // Convert to buffers
      const plainBuffer = Buffer.from(plainToken, 'utf8');
      const expectedBuffer = Buffer.from(expectedToken, 'utf8');

      // Check length first (constant time not needed for length comparison)
      if (plainBuffer.length !== expectedBuffer.length) {
        return false;
      }

      // Constant-time comparison
      return crypto.timingSafeEqual(plainBuffer, expectedBuffer);
    } catch (error) {
      // Buffer conversion or comparison failed
      return false;
    }
  }
}