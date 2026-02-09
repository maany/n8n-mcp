/**
 * User Instance Repository
 *
 * Data access layer for user n8n instance configurations.
 * Stores data in auth.db (alongside better-auth tables).
 * Handles encrypted storage and retrieval of API credentials.
 */

import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { EncryptionService } from '../services/encryption-service';
import { logger } from '../utils/logger';

/**
 * Minimal database interface matching better-sqlite3's API.
 * Allows injecting mocks for testing.
 */
export interface UserInstanceDB {
  prepare(sql: string): {
    run(...params: any[]): { changes: number; lastInsertRowid: number | bigint };
    get(...params: any[]): any;
    all(...params: any[]): any[];
  };
  exec(sql: string): void;
  close(): void;
}

/**
 * User instance configuration with decrypted API key
 */
export interface UserInstance {
  id: string;
  userId: string;
  instanceName: string;
  n8nApiUrl: string;
  n8nApiKey: string;
  isDefault: boolean;
  timeoutMs: number;
  maxRetries: number;
  metadata?: Record<string, unknown>;
  verificationStatus: 'unverified' | 'valid' | 'invalid' | 'expired';
  lastVerifiedAt?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * User instance without the decrypted API key (for listing)
 */
export interface UserInstanceSummary {
  id: string;
  userId: string;
  instanceName: string;
  n8nApiUrl: string;
  isDefault: boolean;
  timeoutMs: number;
  maxRetries: number;
  verificationStatus: 'unverified' | 'valid' | 'invalid' | 'expired';
  lastVerifiedAt?: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Input for creating a new user instance
 */
export interface CreateUserInstanceInput {
  userId: string;
  instanceName: string;
  n8nApiUrl: string;
  n8nApiKey: string;
  isDefault?: boolean;
  timeoutMs?: number;
  maxRetries?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Input for updating a user instance (excluding API key)
 */
export interface UpdateUserInstanceInput {
  instanceName?: string;
  n8nApiUrl?: string;
  isDefault?: boolean;
  timeoutMs?: number;
  maxRetries?: number;
  metadata?: Record<string, unknown>;
}

// Singleton instance
let singleton: UserInstanceRepository | null = null;

/**
 * Repository for managing user n8n instance configurations.
 * Uses auth.db for storage.
 */
export class UserInstanceRepository {
  private db: UserInstanceDB;
  private encryption: EncryptionService;

  constructor(db: UserInstanceDB, encryption: EncryptionService) {
    this.db = db;
    this.encryption = encryption;
  }

  /**
   * Get or create the singleton repository connected to auth.db.
   * Creates the tables if they don't exist.
   * Returns null if encryption is not configured.
   */
  static getInstance(): UserInstanceRepository | null {
    if (singleton) return singleton;

    const encryption = EncryptionService.getInstance();
    if (!encryption) return null;

    try {
      // Import better-sqlite3 dynamically (same as auth.ts)
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const Database = require('better-sqlite3');
      const dbPath = path.join(process.cwd(), 'data', 'auth.db');
      const db = new Database(dbPath);

      // Enable WAL mode for better concurrent access
      db.pragma('journal_mode = WAL');
      db.pragma('foreign_keys = ON');

      singleton = new UserInstanceRepository(db, encryption);
      logger.info('UserInstanceRepository initialized with auth.db');
      return singleton;
    } catch (error) {
      logger.error('Failed to initialize UserInstanceRepository:', error);
      return null;
    }
  }

  /**
   * Reset singleton (for testing)
   */
  static resetInstance(): void {
    singleton = null;
  }

  /**
   * Create a new user instance configuration
   */
  createUserInstance(input: CreateUserInstanceInput): UserInstance {
    const id = uuidv4();
    const encrypted = this.encryption.encrypt(input.n8nApiKey);
    const now = new Date().toISOString();

    // If setting as default, clear other defaults first
    if (input.isDefault) {
      this.db.prepare(`
        UPDATE user_instances SET is_default = 0, updated_at = ? WHERE user_id = ?
      `).run(now, input.userId);
    }

    this.db.prepare(`
      INSERT INTO user_instances (
        id, user_id, instance_name, n8n_api_url,
        n8n_api_key_encrypted, n8n_api_key_iv, n8n_api_key_auth_tag,
        is_default, timeout_ms, max_retries, metadata,
        verification_status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unverified', ?, ?)
    `).run(
      id,
      input.userId,
      input.instanceName,
      input.n8nApiUrl,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      input.isDefault ? 1 : 0,
      input.timeoutMs ?? 30000,
      input.maxRetries ?? 3,
      input.metadata ? JSON.stringify(input.metadata) : null,
      now,
      now
    );

    return this.getUserInstance(id)!;
  }

  /**
   * Get a user instance by ID with decrypted API key
   */
  getUserInstance(id: string): UserInstance | null {
    const row = this.db.prepare(`
      SELECT * FROM user_instances WHERE id = ?
    `).get(id) as any;

    if (!row) return null;
    return this.parseRowWithKey(row);
  }

  /**
   * Get a user instance by ID for a specific user (with ownership check)
   */
  getUserInstanceForUser(id: string, userId: string): UserInstance | null {
    const row = this.db.prepare(`
      SELECT * FROM user_instances WHERE id = ? AND user_id = ?
    `).get(id, userId) as any;

    if (!row) return null;
    return this.parseRowWithKey(row);
  }

  /**
   * Get all instances for a user (without API keys)
   */
  getUserInstances(userId: string): UserInstanceSummary[] {
    const rows = this.db.prepare(`
      SELECT * FROM user_instances
      WHERE user_id = ?
      ORDER BY is_default DESC, instance_name ASC
    `).all(userId) as any[];

    return rows.map(row => this.parseRowSummary(row));
  }

  /**
   * Get user's default instance with decrypted API key
   */
  getDefaultInstance(userId: string): UserInstance | null {
    const row = this.db.prepare(`
      SELECT * FROM user_instances
      WHERE user_id = ? AND is_default = 1
      LIMIT 1
    `).get(userId) as any;

    if (!row) return null;
    return this.parseRowWithKey(row);
  }

  /**
   * Get instance by name for a user
   */
  getInstanceByName(userId: string, instanceName: string): UserInstance | null {
    const row = this.db.prepare(`
      SELECT * FROM user_instances
      WHERE user_id = ? AND instance_name = ?
    `).get(userId, instanceName) as any;

    if (!row) return null;
    return this.parseRowWithKey(row);
  }

  /**
   * Update instance (excluding API key)
   */
  updateUserInstance(id: string, userId: string, updates: UpdateUserInstanceInput): UserInstance | null {
    const existing = this.getUserInstanceForUser(id, userId);
    if (!existing) return null;

    const setClauses: string[] = ['updated_at = ?'];
    const params: any[] = [new Date().toISOString()];

    if (updates.instanceName !== undefined) {
      setClauses.push('instance_name = ?');
      params.push(updates.instanceName);
    }

    if (updates.n8nApiUrl !== undefined) {
      setClauses.push('n8n_api_url = ?');
      params.push(updates.n8nApiUrl);
      // URL change invalidates verification
      setClauses.push("verification_status = 'unverified'");
    }

    if (updates.timeoutMs !== undefined) {
      setClauses.push('timeout_ms = ?');
      params.push(updates.timeoutMs);
    }

    if (updates.maxRetries !== undefined) {
      setClauses.push('max_retries = ?');
      params.push(updates.maxRetries);
    }

    if (updates.metadata !== undefined) {
      setClauses.push('metadata = ?');
      params.push(JSON.stringify(updates.metadata));
    }

    if (updates.isDefault !== undefined) {
      // Clear other defaults first if setting this as default
      if (updates.isDefault) {
        this.db.prepare(`
          UPDATE user_instances SET is_default = 0, updated_at = ? WHERE user_id = ? AND id != ?
        `).run(new Date().toISOString(), userId, id);
      }
      setClauses.push('is_default = ?');
      params.push(updates.isDefault ? 1 : 0);
    }

    params.push(id, userId);

    this.db.prepare(`
      UPDATE user_instances SET ${setClauses.join(', ')} WHERE id = ? AND user_id = ?
    `).run(...params);

    return this.getUserInstance(id);
  }

  /**
   * Update API key (re-encrypts)
   */
  updateApiKey(id: string, userId: string, newApiKey: string): boolean {
    const existing = this.getUserInstanceForUser(id, userId);
    if (!existing) return false;

    const encrypted = this.encryption.encrypt(newApiKey);
    const now = new Date().toISOString();

    this.db.prepare(`
      UPDATE user_instances
      SET n8n_api_key_encrypted = ?,
          n8n_api_key_iv = ?,
          n8n_api_key_auth_tag = ?,
          verification_status = 'unverified',
          updated_at = ?
      WHERE id = ? AND user_id = ?
    `).run(
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      now,
      id,
      userId
    );

    return true;
  }

  /**
   * Set instance as default
   */
  setDefaultInstance(id: string, userId: string): boolean {
    const existing = this.getUserInstanceForUser(id, userId);
    if (!existing) return false;

    const now = new Date().toISOString();

    // Clear other defaults
    this.db.prepare(`
      UPDATE user_instances SET is_default = 0, updated_at = ? WHERE user_id = ?
    `).run(now, userId);

    // Set this one as default
    this.db.prepare(`
      UPDATE user_instances SET is_default = 1, updated_at = ? WHERE id = ? AND user_id = ?
    `).run(now, id, userId);

    return true;
  }

  /**
   * Update verification status
   */
  updateVerificationStatus(id: string, status: 'valid' | 'invalid' | 'expired'): void {
    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE user_instances
      SET verification_status = ?,
          last_verified_at = ?,
          updated_at = ?
      WHERE id = ?
    `).run(status, now, now, id);
  }

  /**
   * Delete a user instance
   */
  deleteUserInstance(id: string, userId: string): boolean {
    const result = this.db.prepare(`
      DELETE FROM user_instances WHERE id = ? AND user_id = ?
    `).run(id, userId);

    return result.changes > 0;
  }

  /**
   * Delete all instances for a user
   */
  deleteUserInstances(userId: string): number {
    const result = this.db.prepare(`
      DELETE FROM user_instances WHERE user_id = ?
    `).run(userId);

    return result.changes;
  }

  /**
   * Count instances for a user
   */
  countUserInstances(userId: string): number {
    const row = this.db.prepare(`
      SELECT COUNT(*) as count FROM user_instances WHERE user_id = ?
    `).get(userId) as { count: number };

    return row.count;
  }

  /**
   * Parse a database row into UserInstance with decrypted API key
   */
  private parseRowWithKey(row: any): UserInstance {
    const decryptedKey = this.encryption.decrypt({
      ciphertext: row.n8n_api_key_encrypted,
      iv: row.n8n_api_key_iv,
      authTag: row.n8n_api_key_auth_tag
    });

    return {
      id: row.id,
      userId: row.user_id,
      instanceName: row.instance_name,
      n8nApiUrl: row.n8n_api_url,
      n8nApiKey: decryptedKey,
      isDefault: row.is_default === 1,
      timeoutMs: row.timeout_ms,
      maxRetries: row.max_retries,
      metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
      verificationStatus: row.verification_status,
      lastVerifiedAt: row.last_verified_at || undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  /**
   * Parse a database row into UserInstanceSummary (no API key)
   */
  private parseRowSummary(row: any): UserInstanceSummary {
    return {
      id: row.id,
      userId: row.user_id,
      instanceName: row.instance_name,
      n8nApiUrl: row.n8n_api_url,
      isDefault: row.is_default === 1,
      timeoutMs: row.timeout_ms,
      maxRetries: row.max_retries,
      verificationStatus: row.verification_status,
      lastVerifiedAt: row.last_verified_at || undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }
}
