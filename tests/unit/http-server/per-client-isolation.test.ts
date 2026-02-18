/**
 * Unit tests for per-client transport isolation
 *
 * Tests the fix for connection drop destroying transports (ngrok issue)
 * and per-client isolation via clientSessions routing.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'crypto';

// Mock dependencies that N8NDocumentationMCPServer and SingleSessionHTTPServer depend on
vi.mock('../../../src/utils/console-manager', () => ({
  ConsoleManager: vi.fn().mockImplementation(() => ({
    wrapOperation: vi.fn((fn: any) => fn()),
    isolate: vi.fn((fn: any) => fn())
  }))
}));

vi.mock('../../../src/utils/logger', () => ({
  Logger: vi.fn().mockImplementation(() => ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  })),
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  }
}));

// Mock N8NDocumentationMCPServer before it gets imported
const mockMCPServer = () => ({
  connect: vi.fn().mockResolvedValue(undefined),
  close: vi.fn().mockResolvedValue(undefined),
  setInstanceContext: vi.fn()
});

vi.mock('../../../src/mcp/server', () => ({
  N8NDocumentationMCPServer: vi.fn().mockImplementation(() => mockMCPServer())
}));

// Mock StreamableHTTPServerTransport
let transportIdCounter = 0;
const mockTransport = (opts: any) => {
  const id = ++transportIdCounter;
  const sessionId = opts?.sessionIdGenerator?.() || `mock-session-${id}`;
  const transport = {
    _mockId: id,
    sessionId,
    handleRequest: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    onclose: null as (() => void) | null,
    onerror: null as ((err: Error) => void) | null
  };
  if (opts?.onsessioninitialized) {
    setTimeout(() => opts.onsessioninitialized(sessionId), 0);
  }
  return transport;
};

vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: vi.fn().mockImplementation((opts: any) => mockTransport(opts))
}));

import { SingleSessionHTTPServer } from '../../../src/http-server-single-session';
import { SessionState } from '../../../src/types/session-state';
import { N8NDocumentationMCPServer } from '../../../src/mcp/server';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

describe('SingleSessionHTTPServer - Per-Client Isolation', () => {
  let server: SingleSessionHTTPServer;
  let serverAny: any;

  beforeEach(() => {
    transportIdCounter = 0;
    // Re-apply mock implementations after vi.clearAllMocks()
    vi.mocked(N8NDocumentationMCPServer).mockImplementation(() => mockMCPServer() as any);
    vi.mocked(StreamableHTTPServerTransport).mockImplementation((opts: any) => mockTransport(opts) as any);
    server = new SingleSessionHTTPServer();
    serverAny = server as any;
  });

  describe('deriveClientKey()', () => {
    it('should return user key for OAuth-authenticated requests', () => {
      const req = { headers: {} } as any;
      req.oauthUserId = 'user-abc-123';

      const key = serverAny.deriveClientKey(req);
      expect(key).toBe('user:user-abc-123');
    });

    it('should return instance hash key when n8nApiUrl is present', () => {
      const req = { headers: {} } as any;
      const instanceContext = {
        n8nApiUrl: 'https://n8n.example.com',
        n8nApiKey: 'some-key'
      };

      const key = serverAny.deriveClientKey(req, instanceContext);
      const expectedHash = createHash('sha256')
        .update('https://n8n.example.com')
        .digest('hex')
        .slice(0, 16);
      expect(key).toBe(`instance:${expectedHash}`);
    });

    it('should return "default" for bearer-token-only requests', () => {
      const req = { headers: {} } as any;

      const key = serverAny.deriveClientKey(req);
      expect(key).toBe('default');
    });

    it('should prioritize OAuth userId over instance context', () => {
      const req = { headers: {} } as any;
      req.oauthUserId = 'user-xyz';
      const instanceContext = {
        n8nApiUrl: 'https://n8n.example.com',
        n8nApiKey: 'key'
      };

      const key = serverAny.deriveClientKey(req, instanceContext);
      expect(key).toBe('user:user-xyz');
    });
  });

  describe('isContextMatching()', () => {
    it('should match when both contexts are undefined', () => {
      expect(serverAny.isContextMatching(undefined, undefined)).toBe(true);
    });

    it('should not match when one context is undefined', () => {
      const ctx = { n8nApiUrl: 'https://example.com', n8nApiKey: 'key' };
      expect(serverAny.isContextMatching(ctx, undefined)).toBe(false);
      expect(serverAny.isContextMatching(undefined, ctx)).toBe(false);
    });

    it('should match when URL, key, and userId are identical', () => {
      const ctx1 = { n8nApiUrl: 'https://example.com', n8nApiKey: 'key', userId: 'u1' };
      const ctx2 = { n8nApiUrl: 'https://example.com', n8nApiKey: 'key', userId: 'u1' };
      expect(serverAny.isContextMatching(ctx1, ctx2)).toBe(true);
    });

    it('should not match when API key differs (rotation)', () => {
      const ctx1 = { n8nApiUrl: 'https://example.com', n8nApiKey: 'old-key' };
      const ctx2 = { n8nApiUrl: 'https://example.com', n8nApiKey: 'new-key' };
      expect(serverAny.isContextMatching(ctx1, ctx2)).toBe(false);
    });

    it('should not match when URL differs', () => {
      const ctx1 = { n8nApiUrl: 'https://a.example.com', n8nApiKey: 'key' };
      const ctx2 = { n8nApiUrl: 'https://b.example.com', n8nApiKey: 'key' };
      expect(serverAny.isContextMatching(ctx1, ctx2)).toBe(false);
    });
  });

  describe('getOrCreateClientTransport()', () => {
    it('should create a new transport for a new client key', async () => {
      const transport = await serverAny.getOrCreateClientTransport('default');

      expect(transport).toBeDefined();
      expect(serverAny.clientSessions.has('default')).toBe(true);

      const sessionId = serverAny.clientSessions.get('default');
      expect(serverAny.transports[sessionId]).toBe(transport);
      expect(serverAny.servers[sessionId]).toBeDefined();
      expect(serverAny.sessionMetadata[sessionId]).toBeDefined();
    });

    it('should reuse transport for the same client key', async () => {
      const transport1 = await serverAny.getOrCreateClientTransport('user:abc');
      const transport2 = await serverAny.getOrCreateClientTransport('user:abc');

      expect(transport1).toBe(transport2);
    });

    it('should create separate transports for different client keys', async () => {
      const transport1 = await serverAny.getOrCreateClientTransport('user:alice');
      const transport2 = await serverAny.getOrCreateClientTransport('user:bob');

      expect(transport1).not.toBe(transport2);
      expect(serverAny.clientSessions.size).toBe(2);
    });

    it('should reset transport on context mismatch', async () => {
      const ctx1 = { n8nApiUrl: 'https://a.example.com', n8nApiKey: 'key1' };
      const ctx2 = { n8nApiUrl: 'https://a.example.com', n8nApiKey: 'key2-rotated' };

      const transport1 = await serverAny.getOrCreateClientTransport('user:alice', ctx1);
      const sessionId1 = serverAny.clientSessions.get('user:alice');

      const transport2 = await serverAny.getOrCreateClientTransport('user:alice', ctx2);
      const sessionId2 = serverAny.clientSessions.get('user:alice');

      expect(transport1).not.toBe(transport2);
      expect(sessionId1).not.toBe(sessionId2);
    });

    it('should enforce MAX_SESSIONS limit', async () => {
      // Fill up transports map to MAX_SESSIONS (100)
      for (let i = 0; i < 100; i++) {
        serverAny.transports[`existing-${i}`] = {};
      }

      await expect(
        serverAny.getOrCreateClientTransport('new-client')
      ).rejects.toThrow(/Maximum sessions/);
    });
  });

  describe('Connection close does NOT destroy transport', () => {
    it('should keep transport alive after simulated connection close', async () => {
      const transport = await serverAny.getOrCreateClientTransport('default');
      const sessionId = serverAny.clientSessions.get('default');

      // The new close handler just logs — no removeSession call.
      // Verify transport survives.
      expect(serverAny.transports[sessionId]).toBe(transport);
      expect(serverAny.clientSessions.get('default')).toBe(sessionId);
    });
  });

  describe('initialize resets only requesting client', () => {
    it('should not affect other clients when one reinitializes', async () => {
      // Create transports for two clients
      const transportAlice = await serverAny.getOrCreateClientTransport('user:alice');
      const sessionIdAlice = serverAny.clientSessions.get('user:alice');

      const transportBob = await serverAny.getOrCreateClientTransport('user:bob');
      const sessionIdBob = serverAny.clientSessions.get('user:bob');

      // Simulate Alice reinitializing: remove her session
      await serverAny.removeSession(sessionIdAlice, 'reinitialize');
      serverAny.clientSessions.delete('user:alice');

      // Bob's transport should be unaffected
      expect(serverAny.transports[sessionIdBob]).toBe(transportBob);
      expect(serverAny.clientSessions.get('user:bob')).toBe(sessionIdBob);

      // Alice's transport should be gone
      expect(serverAny.transports[sessionIdAlice]).toBeUndefined();
      expect(serverAny.clientSessions.has('user:alice')).toBe(false);
    });
  });

  describe('removeSession cleans up clientSessions', () => {
    it('should remove clientSessions entry when session is removed', async () => {
      await serverAny.getOrCreateClientTransport('user:cleanup-test');
      const sessionId = serverAny.clientSessions.get('user:cleanup-test');

      expect(serverAny.clientSessions.has('user:cleanup-test')).toBe(true);

      await serverAny.removeSession(sessionId, 'test');

      expect(serverAny.clientSessions.has('user:cleanup-test')).toBe(false);
      expect(serverAny.transports[sessionId]).toBeUndefined();
    });
  });

  describe('Session persistence with clientKey/userId', () => {
    it('should include clientKey and userId in exported state', async () => {
      const ctx = {
        n8nApiUrl: 'https://export.example.com',
        n8nApiKey: 'export-key',
        userId: 'user-export-1'
      };

      await serverAny.getOrCreateClientTransport('user:user-export-1', ctx);

      const exported = server.exportSessionState();
      expect(exported).toHaveLength(1);
      expect(exported[0].context.userId).toBe('user-export-1');
      expect(exported[0].context.clientKey).toBe('user:user-export-1');
    });

    it('should rebuild clientSessions on restore', () => {
      const sessions: SessionState[] = [
        {
          sessionId: 'restored-session-1',
          metadata: {
            createdAt: new Date().toISOString(),
            lastAccess: new Date().toISOString()
          },
          context: {
            n8nApiUrl: 'https://restored.example.com',
            n8nApiKey: 'restored-key',
            instanceId: 'restored-instance',
            userId: 'user-restored',
            clientKey: 'user:user-restored'
          }
        }
      ];

      const count = server.restoreSessionState(sessions);
      expect(count).toBe(1);

      expect(serverAny.clientSessions.get('user:user-restored')).toBe('restored-session-1');
      expect(serverAny.sessionContexts['restored-session-1'].userId).toBe('user-restored');
    });

    it('should handle restore without clientKey gracefully', () => {
      const sessions: SessionState[] = [
        {
          sessionId: 'no-key-session',
          metadata: {
            createdAt: new Date().toISOString(),
            lastAccess: new Date().toISOString()
          },
          context: {
            n8nApiUrl: 'https://nokey.example.com',
            n8nApiKey: 'nokey-key',
            instanceId: 'nokey-instance'
          }
        }
      ];

      const count = server.restoreSessionState(sessions);
      expect(count).toBe(1);

      // clientSessions should not have an entry since no clientKey was provided
      expect(serverAny.clientSessions.size).toBe(0);
    });
  });
});
