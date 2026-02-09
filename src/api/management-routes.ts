/**
 * Management Routes for OIDC Clients & n8n Instances
 *
 * Provides REST endpoints with dual authentication:
 * - Admin access via AUTH_TOKEN (Bearer token)
 * - User access via better-auth session cookies
 */

import { Router, Request, Response, json } from 'express';
import { auth, AuthManager } from '../utils/auth';
import { fromNodeHeaders } from 'better-auth/node';
import { UserInstanceRepository } from '../database/user-instance-repository';
import { EncryptionService } from '../services/encryption-service';
import { N8nApiClient } from '../services/n8n-api-client';
import { validateInstanceContext } from '../types/instance-context';
import { logger } from '../utils/logger';
import path from 'path';
import Database from 'better-sqlite3';

// Extend Express Request with auth context
interface AuthenticatedRequest extends Request {
  userId?: string;
  isAdmin?: boolean;
}

/**
 * Dual-auth middleware: checks AUTH_TOKEN first, then session cookie
 */
function createRequireAuth(authToken: string | undefined) {
  return async (req: AuthenticatedRequest, res: Response, next: () => void): Promise<void> => {
    // Check Authorization: Bearer <AUTH_TOKEN> first (admin)
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ') && authToken) {
      const token = authHeader.slice(7).trim();
      if (AuthManager.timingSafeCompare(token, authToken)) {
        req.userId = 'admin';
        req.isAdmin = true;
        next();
        return;
      }
    }

    // Try better-auth session cookie
    try {
      const session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      });

      if (session?.user?.id) {
        req.userId = session.user.id;
        req.isAdmin = false;
        next();
        return;
      }
      logger.warn('Management auth: session found but no user ID', {
        path: req.path,
        hasSession: !!session,
      });
    } catch (error: any) {
      logger.warn('Management auth: session verification failed', {
        path: req.path,
        error: error.message || String(error),
      });
    }

    res.status(401).json({ error: 'Unauthorized' });
  };
}

/**
 * Get the repository instance, returning 503 if not configured
 */
function getRepository(res: Response): UserInstanceRepository | null {
  const repo = UserInstanceRepository.getInstance();
  if (!repo) {
    logger.warn('Instance management unavailable: encryption not configured');
    res.status(503).json({
      error: 'Instance management not available',
      detail: 'Encryption key not configured (N8N_MCP_ENCRYPTION_KEY)',
    });
    return null;
  }
  return repo;
}

/**
 * Redact API key for display — show last 4 chars only
 */
function redactApiKey(key: string): string {
  if (key.length <= 4) return '****';
  return '****' + key.slice(-4);
}

/**
 * Extract a single string from an Express v5 param/query value
 */
function str(val: string | string[] | undefined): string {
  if (Array.isArray(val)) return val[0] ?? '';
  return val ?? '';
}

/**
 * Create the management router with dual-auth endpoints
 */
export function createManagementRouter(authToken: string | undefined): Router {
  const router = Router();
  const jsonParser = json();
  const requireAuth = createRequireAuth(authToken);

  // ──────────────────────────────────────────────
  // OIDC Client Endpoints
  // ──────────────────────────────────────────────

  /**
   * GET /api/manage/clients — List OIDC clients
   * Admin: queries oauthClient table directly
   * Session user: proxies to better-auth
   */
  router.get('/clients', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const dbPath = path.join(process.cwd(), 'data', 'auth.db');
      const db = new Database(dbPath, { readonly: true });
      try {
        // Admin sees all clients; session user sees own + unowned clients
        const query = req.isAdmin
          ? `SELECT id, clientId, name, redirectUris, createdAt, type, disabled, userId
             FROM oauthClient ORDER BY createdAt DESC`
          : `SELECT id, clientId, name, redirectUris, createdAt, type, disabled, userId
             FROM oauthClient WHERE userId = ? ORDER BY createdAt DESC`;
        const params = req.isAdmin ? [] : [req.userId];
        const clients = db.prepare(query).all(...params) as any[];

        res.json({
          clients: clients.map((c: any) => ({
            id: c.id,
            clientId: c.clientId,
            clientName: c.name || '',
            redirectURIs: c.redirectUris ? JSON.parse(c.redirectUris) : [],
            createdAt: c.createdAt,
            type: c.type,
            disabled: !!c.disabled,
          })),
        });
      } finally {
        db.close();
      }
    } catch (error: any) {
      logger.error('Failed to list OIDC clients', error);
      res.status(500).json({ error: error.message || 'Failed to list clients' });
    }
  });

  /**
   * POST /api/manage/clients — Register a new OIDC client
   */
  router.post('/clients', requireAuth as any, jsonParser, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { client_name, redirect_uris } = req.body;

      if (!client_name || !redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
        res.status(400).json({
          error: 'client_name and redirect_uris (non-empty array) are required',
        });
        return;
      }

      if (req.isAdmin) {
        // Admin: use better-auth register endpoint directly
        const result = await (auth.api as any).registerOAuthClient({
          body: {
            client_name,
            redirect_uris,
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic',
          },
        });
        res.status(201).json(result);
      } else {
        // Session user: pass session context
        const result = await (auth.api as any).registerOAuthClient({
          headers: fromNodeHeaders(req.headers),
          body: {
            client_name,
            redirect_uris,
            grant_types: ['authorization_code', 'refresh_token'],
            response_types: ['code'],
            token_endpoint_auth_method: 'client_secret_basic',
          },
        });
        res.status(201).json(result);
      }
    } catch (error: any) {
      logger.error('Failed to register OIDC client', error);
      res.status(500).json({ error: error.message || 'Failed to register client' });
    }
  });

  /**
   * DELETE /api/manage/clients/:clientId — Delete an OIDC client
   */
  router.delete('/clients/:clientId', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const clientId = str(req.params.clientId);

      if (req.isAdmin) {
        // Admin: direct DB delete
        const dbPath = path.join(process.cwd(), 'data', 'auth.db');
        const db = new Database(dbPath);
        try {
          const result = db.prepare('DELETE FROM oauthClient WHERE clientId = ?').run(clientId);
          if (result.changes === 0) {
            res.status(404).json({ error: 'Client not found' });
            return;
          }
          res.json({ success: true });
        } finally {
          db.close();
        }
      } else {
        // Session user: use better-auth API
        await (auth.api as any).deleteOAuthClient({
          headers: fromNodeHeaders(req.headers),
          body: { clientId },
        });
        res.json({ success: true });
      }
    } catch (error: any) {
      logger.error('Failed to delete OIDC client', error);
      res.status(500).json({ error: error.message || 'Failed to delete client' });
    }
  });

  // ──────────────────────────────────────────────
  // n8n Instance Endpoints
  // ──────────────────────────────────────────────

  /**
   * GET /api/manage/instances — List user's n8n instances
   */
  router.get('/instances', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      if (req.isAdmin && req.query.userId) {
        // Admin can query any user's instances
        const repo = getRepository(res);
        if (!repo) return;
        const instances = repo.getUserInstances(str(req.query.userId as string));
        res.json({ instances });
        return;
      }

      if (req.isAdmin && !req.query.userId) {
        res.status(400).json({
          error: 'Admin must specify userId query parameter',
        });
        return;
      }

      const repo = getRepository(res);
      if (!repo) return;
      const instances = repo.getUserInstances(req.userId!);
      res.json({ instances });
    } catch (error: any) {
      logger.error('Failed to list instances', error);
      res.status(500).json({ error: error.message || 'Failed to list instances' });
    }
  });

  /**
   * POST /api/manage/instances — Create a new n8n instance
   */
  router.post('/instances', requireAuth as any, jsonParser, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { instanceName, n8nApiUrl, n8nApiKey, isDefault, timeoutMs, maxRetries } = req.body;

      if (!instanceName || !n8nApiUrl || !n8nApiKey) {
        res.status(400).json({
          error: 'instanceName, n8nApiUrl, and n8nApiKey are required',
        });
        return;
      }

      // Validate URL and API key
      const validation = validateInstanceContext({
        n8nApiUrl,
        n8nApiKey,
        n8nApiTimeout: timeoutMs,
        n8nApiMaxRetries: maxRetries,
      });

      if (!validation.valid) {
        res.status(400).json({ error: 'Validation failed', details: validation.errors });
        return;
      }

      const userId = req.isAdmin ? (req.body.userId || req.userId!) : req.userId!;
      if (req.isAdmin && !req.body.userId) {
        res.status(400).json({ error: 'Admin must specify userId in body' });
        return;
      }

      const repo = getRepository(res);
      if (!repo) return;

      const instance = repo.createUserInstance({
        userId,
        instanceName,
        n8nApiUrl,
        n8nApiKey,
        isDefault: isDefault ?? false,
        timeoutMs: timeoutMs ?? 30000,
        maxRetries: maxRetries ?? 3,
      });

      // Return summary without decrypted key
      res.status(201).json({
        instance: {
          id: instance.id,
          instanceName: instance.instanceName,
          n8nApiUrl: instance.n8nApiUrl,
          n8nApiKeyRedacted: redactApiKey(n8nApiKey),
          isDefault: instance.isDefault,
          timeoutMs: instance.timeoutMs,
          maxRetries: instance.maxRetries,
          verificationStatus: instance.verificationStatus,
          createdAt: instance.createdAt,
        },
      });
    } catch (error: any) {
      logger.error('Failed to create instance', error);
      res.status(500).json({ error: error.message || 'Failed to create instance' });
    }
  });

  /**
   * DELETE /api/manage/instances/:id — Delete an n8n instance
   */
  router.delete('/instances/:id', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = str(req.params.id);
      const repo = getRepository(res);
      if (!repo) return;

      const userId = req.isAdmin ? (str(req.query.userId as string) || req.userId!) : req.userId!;
      if (req.isAdmin && !req.query.userId) {
        res.status(400).json({ error: 'Admin must specify userId query parameter' });
        return;
      }

      const deleted = repo.deleteUserInstance(id, userId);
      if (!deleted) {
        res.status(404).json({ error: 'Instance not found or not owned by user' });
        return;
      }

      res.json({ success: true });
    } catch (error: any) {
      logger.error('Failed to delete instance', error);
      res.status(500).json({ error: error.message || 'Failed to delete instance' });
    }
  });

  /**
   * POST /api/manage/instances/:id/verify — Verify n8n instance connectivity
   */
  router.post('/instances/:id/verify', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = str(req.params.id);
      const repo = getRepository(res);
      if (!repo) return;

      const userId = req.isAdmin ? (str(req.query.userId as string) || req.userId!) : req.userId!;
      if (req.isAdmin && !req.query.userId) {
        res.status(400).json({ error: 'Admin must specify userId query parameter' });
        return;
      }

      // Get instance with decrypted key
      const instance = repo.getUserInstanceForUser(id, userId);
      if (!instance) {
        res.status(404).json({ error: 'Instance not found or not owned by user' });
        return;
      }

      // Attempt to connect to n8n
      const client = new N8nApiClient({
        baseUrl: instance.n8nApiUrl,
        apiKey: instance.n8nApiKey,
        timeout: instance.timeoutMs,
        maxRetries: 1,
      });

      try {
        await client.listWorkflows({ limit: 1 });
        repo.updateVerificationStatus(id, 'valid');
        res.json({ status: 'valid', message: 'Connection successful' });
      } catch (connError: any) {
        repo.updateVerificationStatus(id, 'invalid');
        res.json({
          status: 'invalid',
          message: `Connection failed: ${connError.message || 'Unknown error'}`,
        });
      }
    } catch (error: any) {
      logger.error('Failed to verify instance', error);
      res.status(500).json({ error: error.message || 'Failed to verify instance' });
    }
  });

  /**
   * PATCH /api/manage/instances/:id/default — Set as default instance
   */
  router.patch('/instances/:id/default', requireAuth as any, async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = str(req.params.id);
      const repo = getRepository(res);
      if (!repo) return;

      const userId = req.isAdmin ? (str(req.query.userId as string) || req.userId!) : req.userId!;
      if (req.isAdmin && !req.query.userId) {
        res.status(400).json({ error: 'Admin must specify userId query parameter' });
        return;
      }

      const success = repo.setDefaultInstance(id, userId);
      if (!success) {
        res.status(404).json({ error: 'Instance not found or not owned by user' });
        return;
      }

      res.json({ success: true });
    } catch (error: any) {
      logger.error('Failed to set default instance', error);
      res.status(500).json({ error: error.message || 'Failed to set default instance' });
    }
  });

  return router;
}
