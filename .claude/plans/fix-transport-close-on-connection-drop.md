# Fix Transport Close on Connection Drop + Per-Client Isolation

## Problem

Two issues in `src/http-server-single-session.ts`:

1. **Connection drop bug**: When an HTTP connection drops through ngrok, `req.on('close')` (line 1661) fires. If `timeSinceAccess > 60s`, it calls `removeSession()` which destroys the transport. The SDK's `Protocol._onclose` permanently disconnects the server. New requests create an uninitialized transport → perpetual 400 "Server not initialized" errors.

2. **Shared transport security flaw**: ALL clients share ONE transport. The `instanceContext` (n8n API URL + key) is bound at creation (line 148) and never switched. Client B inherits Client A's credentials. Any client sending `initialize` resets everyone's session (line 573-575).

### Root Cause Timeline (from 2026-02-17 logs)

1. **13:45:26** — Last `updateSessionAccess` for session `c9c9c815`
2. **13:46:27.484** — New `tools/call` POST arrives, connection drops immediately
3. **13:46:27.485** — `req.on('close')` fires → `timeSinceAccess` = 61s → guard passes → `removeSession()`
4. **13:46:27.487** — `removeSession` → `transport.close()` → SDK `Protocol._onclose` → server permanently disconnected
5. **13:46:27.565** — Next request → creates new uninitialized transport → 400 forever

## Fix: Per-Client Transport Keying

Replace the single shared transport with per-client transports routed by a derived **client key**. No client-side changes required — routing is entirely server-side based on the OAuth token's `userId`.

| Auth method | Client key | Behavior |
|---|---|---|
| OAuth (ENABLE_OAUTH=true) | `user:{userId}` | Per-user isolation |
| Explicit headers (x-n8n-url) | `instance:{sha256(url).slice(0,16)}` | Per-instance isolation |
| Bearer token only | `"default"` | Single shared transport (backward-compatible) |

The existing `transports`, `servers`, `sessionMetadata`, `sessionContexts` maps are already keyed by sessionId. We add a `clientSessions: Map<clientKey, sessionId>` routing layer on top.

## Changes

### File: `src/http-server-single-session.ts`

#### A. Add `clientSessions` field (after line 117)

```typescript
private clientSessions: Map<string, string> = new Map(); // clientKey → sessionId
```

Mark `singleTransport`, `singleServer`, `singleSessionId` as deprecated (keep for now to avoid breakage).

#### B. Add `deriveClientKey(req, instanceContext?)` helper (after line 362)

Derives routing key from request:
- Priority 1: `(req as any).oauthUserId` → `"user:{userId}"`
- Priority 2: `instanceContext?.n8nApiUrl` → `"instance:{sha256(url).slice(0,16)}"`
- Priority 3: `"default"` (backward-compatible single transport)

#### C. Add `isContextMatching(ctx1, ctx2)` helper

Compares `n8nApiUrl`, `n8nApiKey`, `userId` between stored and incoming context. Used to detect credential rotation or mismatch.

#### D. Replace `getOrCreateSingleTransport` (lines 143-190) with `getOrCreateClientTransport(clientKey, instanceContext?)`

1. Look up `sessionId = clientSessions.get(clientKey)`
2. If transport exists AND `isContextMatching` → return it, update `lastAccess`
3. If transport exists AND context **mismatches** → `removeSession()`, delete client key, recreate
4. If `!canCreateSession()` → throw (MAX_SESSIONS enforced, line 297-298)
5. Create new `N8NDocumentationMCPServer(instanceContext)` + `StreamableHTTPServerTransport`
6. `onclose` handler: clean up `clientSessions` entry + all maps
7. Register in `clientSessions` and all maps

#### E. Update `handleRequest` (lines 556-600)

```
1. Derive clientKey from (req, instanceContext)
2. If method === 'initialize' AND transport exists for this clientKey:
   - Reset ONLY this client's transport (not all clients)
3. Get/create transport via getOrCreateClientTransport(clientKey, instanceContext)
4. Delegate to transport.handleRequest(req, res, req.body)
```

Replaces `resetSingleSession()` call at line 573-575 with per-client reset.

#### F. Fix connection close handler (lines 1660-1686)

Remove `removeSession` call entirely. Only log. Periodic `cleanupExpiredSessions()` (every 5 min, 5-min timeout) handles true session expiry.

```typescript
const closeHandler = () => {
  if (sessionId) {
    logger.debug('HTTP connection closed', { sessionId, headersSent: res.headersSent });
    // Don't destroy transport — periodic cleanup handles expiry
  }
};
```

This is the core bug fix. Transient ngrok drops no longer destroy transports.

#### G. Update `removeSession` (lines 251-289)

Add reverse-lookup cleanup: iterate `clientSessions` to find and delete the entry for the removed sessionId.

#### H. Update `exportSessionState` / `restoreSessionState`

- **Export**: Include `clientKey` in `context.metadata` and `userId` in `context`
- **Restore**: Rebuild `clientSessions` map from exported metadata

### File: `src/types/session-state.ts`

Add optional `userId` field to `SessionState.context` (after line 84):

```typescript
userId?: string; // For client key derivation on restore
```

### New test file: `tests/unit/http-server/per-client-isolation.test.ts`

- Client key derivation (OAuth → user key, headers → instance key, bearer → "default")
- Separate transports for different OAuth users
- Transport reuse for same client key
- Context mismatch triggers reset (not shared with other clients)
- `initialize` resets only requesting client's transport
- Connection close does NOT destroy transport
- MAX_SESSIONS enforcement

### Update existing tests

- `tests/unit/http-server/session-persistence.test.ts` — expect `userId`/`clientKey` in exports
- `tests/unit/http-server/multi-tenant-support.test.ts` — expect per-client isolation

## Edge Cases

| Scenario | Handling |
|---|---|
| Same user, rotated API key | `isContextMatching` detects mismatch → reset + recreate |
| Concurrent `initialize` from same client | Sequential — first creates, second resets and recreates |
| MAX_SESSIONS exhausted | Return 500, periodic cleanup frees slots |
| Orphaned sessions (crash) | Periodic cleanup removes after timeout (5 min) |
| Bearer token only (single-tenant) | clientKey = `"default"` → one transport, no behavior change |

## Backward Compatibility

- **Single-tenant (bearer token, no OAuth)**: clientKey = `"default"` → identical to current behavior
- **No env var changes needed**: `SESSION_TIMEOUT_MINUTES`, `N8N_MCP_MAX_SESSIONS`, `ENABLE_OAUTH` all work as before
- **No client changes needed**: OAuth token already sent as `Authorization: Bearer <token>`, server derives userId server-side. Standard MCP clients already send `initialize` + `mcp-session-id`.
- **Session persistence**: New `userId`/`clientKey` fields are optional — old exports restore fine

## Verification

1. **Unit tests**: `npm test -- tests/unit/http-server/per-client-isolation.test.ts`
2. **All tests**: `npm test` — existing tests must pass
3. **Connection drop fix**: Deploy via ngrok, call `n8n_create_workflow`, wait >60s idle, call again — no 400s
4. **Multi-tenant isolation**: Connect with two OAuth tokens, verify each gets separate n8n instance context
5. **Single-tenant compat**: Connect with bearer token only, verify unchanged behavior
6. **DELETE /mcp**: Verify explicit session termination still works

## Risk Assessment

- **Low risk**: Bearer-token-only deployments get identical behavior (`"default"` client key)
- **No immortal sessions**: Each transport's `lastAccess` only updated by requests to THAT transport (not all clients)
- **No memory leak**: Periodic cleanup (5 min) + MAX_SESSIONS (100) bound resource usage
- **Rollback safe**: Revert code, old session exports ignore unknown fields
