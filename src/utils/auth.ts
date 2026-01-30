import crypto from 'crypto';
import path from 'path';
import { betterAuth } from "better-auth";
import Database from "better-sqlite3";

import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { toNodeHandler } from "better-auth/node";

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
            validAudiences: [
                process.env.BETTER_AUTH_URL || "http://localhost:3000"
            ],
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
 * Verify OAuth access token by checking the database
 * Returns { valid: false } when OAuth is disabled
 *
 * Note: We query the database directly instead of using the introspection endpoint
 * because the endpoint requires client authentication, which public clients don't have.
 * Since we run both the auth server and resource server in the same process,
 * direct database access is more efficient and secure.
 */
export async function verifyOAuthToken(token: string): Promise<{
    valid: boolean;
    userId?: string;
    scopes?: string[];
}> {
    if (process.env.ENABLE_OAUTH !== 'true') {
        return { valid: false };
    }

    try {
        // Hash the token to match the database storage
        // Better-auth stores hashed tokens using SHA-256 with URL-safe base64 encoding
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
        console.error('OAuth token verification failed:', error);
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