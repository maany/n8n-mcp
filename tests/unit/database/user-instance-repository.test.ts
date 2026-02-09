import { describe, it, expect, beforeEach, vi } from 'vitest';
import { UserInstanceRepository, UserInstance, CreateUserInstanceInput, UserInstanceDB } from '@/database/user-instance-repository';

// Mock encryption service
vi.mock('@/services/encryption-service');

// Create a complete mock for UserInstanceDB (better-sqlite3-compatible interface)
class MockUserInstanceDB implements UserInstanceDB {
  private mockData = new Map<string, any>();

  prepare = vi.fn((sql: string) => {
    return new MockStatement(sql, this.mockData);
  });

  exec = vi.fn();
  close = vi.fn();

  _setMockData(key: string, value: any) {
    this.mockData.set(key, value);
  }

  _getMockData(key: string): any {
    return this.mockData.get(key);
  }

  _clearMockData() {
    this.mockData.clear();
  }
}

class MockStatement {
  run = vi.fn((..._params: any[]): { changes: number; lastInsertRowid: number | bigint } => ({ changes: 1, lastInsertRowid: 1 }));
  get = vi.fn();
  all = vi.fn(() => []);

  constructor(
    private sql: string,
    private mockData: Map<string, any>
  ) {
    this.setupMocks();
  }

  private setupMocks() {
    // User instance queries
    if (this.sql.includes('SELECT * FROM user_instances WHERE id = ?') && !this.sql.includes('user_id')) {
      this.get = vi.fn((id: string) => this.mockData.get(`instance:${id}`));
    }

    if (this.sql.includes('SELECT * FROM user_instances WHERE id = ? AND user_id = ?')) {
      this.get = vi.fn((id: string, userId: string) => {
        const instance = this.mockData.get(`instance:${id}`);
        return instance?.user_id === userId ? instance : null;
      });
    }

    if (this.sql.includes('SELECT * FROM user_instances') && this.sql.includes('WHERE user_id = ?') && this.sql.includes('ORDER BY')) {
      this.all = vi.fn((userId: string) => {
        const instances: any[] = [];
        this.mockData.forEach((value, key) => {
          if (key.startsWith('instance:') && value.user_id === userId) {
            instances.push(value);
          }
        });
        return instances.sort((a, b) => b.is_default - a.is_default);
      });
    }

    if (this.sql.includes('WHERE user_id = ? AND is_default = 1')) {
      this.get = vi.fn((userId: string) => {
        let defaultInstance = null;
        this.mockData.forEach((value, key) => {
          if (key.startsWith('instance:') && value.user_id === userId && value.is_default === 1) {
            defaultInstance = value;
          }
        });
        return defaultInstance;
      });
    }

    if (this.sql.includes('WHERE user_id = ? AND instance_name = ?')) {
      this.get = vi.fn((userId: string, instanceName: string) => {
        let found = null;
        this.mockData.forEach((value, key) => {
          if (key.startsWith('instance:') && value.user_id === userId && value.instance_name === instanceName) {
            found = value;
          }
        });
        return found;
      });
    }

    // Count query
    if (this.sql.includes('SELECT COUNT(*)')) {
      this.get = vi.fn((userId: string) => {
        let count = 0;
        this.mockData.forEach((value, key) => {
          if (key.startsWith('instance:') && value.user_id === userId) {
            count++;
          }
        });
        return { count };
      });
    }
  }
}

describe('UserInstanceRepository', () => {
  let repository: UserInstanceRepository;
  let mockDb: MockUserInstanceDB;
  let mockEncryption: any;

  const testUserId = 'user-123';
  const testInstanceId = 'instance-456';
  const testApiKey = 'n8n_api_key_secret_12345';

  const mockEncryptedData = {
    ciphertext: 'encrypted_ciphertext',
    iv: 'random_iv_base64',
    authTag: 'auth_tag_base64'
  };

  const mockInstanceRow = {
    id: testInstanceId,
    user_id: testUserId,
    instance_name: 'Production',
    n8n_api_url: 'https://n8n.example.com',
    n8n_api_key_encrypted: mockEncryptedData.ciphertext,
    n8n_api_key_iv: mockEncryptedData.iv,
    n8n_api_key_auth_tag: mockEncryptedData.authTag,
    is_default: 1,
    timeout_ms: 30000,
    max_retries: 3,
    metadata: null,
    verification_status: 'unverified',
    last_verified_at: null,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z'
  };

  beforeEach(() => {
    vi.clearAllMocks();

    mockDb = new MockUserInstanceDB();

    // Setup mock encryption service
    mockEncryption = {
      encrypt: vi.fn().mockReturnValue(mockEncryptedData),
      decrypt: vi.fn().mockReturnValue(testApiKey)
    };

    repository = new UserInstanceRepository(mockDb, mockEncryption);

    // Setup default mock data
    mockDb._setMockData(`instance:${testInstanceId}`, mockInstanceRow);
  });

  describe('createUserInstance', () => {
    it('should create instance with encrypted API key', () => {
      const input: CreateUserInstanceInput = {
        userId: testUserId,
        instanceName: 'Development',
        n8nApiUrl: 'https://dev.n8n.example.com',
        n8nApiKey: testApiKey,
        isDefault: false
      };

      // The create should call encrypt
      repository.createUserInstance(input);

      expect(mockEncryption.encrypt).toHaveBeenCalledWith(testApiKey);
    });

    it('should clear other defaults when setting as default', () => {
      const input: CreateUserInstanceInput = {
        userId: testUserId,
        instanceName: 'New Default',
        n8nApiUrl: 'https://new.n8n.example.com',
        n8nApiKey: testApiKey,
        isDefault: true
      };

      repository.createUserInstance(input);

      // Should have called UPDATE to clear defaults
      const updateCalls = mockDb.prepare.mock.calls.filter(
        call => call[0].includes('UPDATE user_instances SET is_default = 0')
      );
      expect(updateCalls.length).toBeGreaterThan(0);
    });
  });

  describe('getUserInstance', () => {
    it('should return instance with decrypted API key', () => {
      const instance = repository.getUserInstance(testInstanceId);

      expect(instance).toBeDefined();
      expect(instance!.id).toBe(testInstanceId);
      expect(instance!.n8nApiKey).toBe(testApiKey);
      expect(mockEncryption.decrypt).toHaveBeenCalledWith(mockEncryptedData);
    });

    it('should return null for non-existent instance', () => {
      const instance = repository.getUserInstance('non-existent-id');
      expect(instance).toBeNull();
    });
  });

  describe('getUserInstances', () => {
    it('should return all instances for user without API keys', () => {
      const instances = repository.getUserInstances(testUserId);

      expect(Array.isArray(instances)).toBe(true);
    });
  });

  describe('getDefaultInstance', () => {
    it('should return default instance with decrypted API key', () => {
      const instance = repository.getDefaultInstance(testUserId);

      expect(instance).toBeDefined();
      expect(instance!.isDefault).toBe(true);
      expect(instance!.n8nApiKey).toBe(testApiKey);
    });

    it('should return null when no default instance', () => {
      mockDb._clearMockData();
      const instance = repository.getDefaultInstance(testUserId);
      expect(instance).toBeNull();
    });
  });

  describe('updateUserInstance', () => {
    it('should update instance metadata', () => {
      const updated = repository.updateUserInstance(testInstanceId, testUserId, {
        instanceName: 'Updated Name'
      });

      expect(mockDb.prepare).toHaveBeenCalled();
    });

    it('should invalidate verification when URL changes', () => {
      repository.updateUserInstance(testInstanceId, testUserId, {
        n8nApiUrl: 'https://new-url.example.com'
      });

      // Should include verification_status = 'unverified' in the update
      const updateCalls = mockDb.prepare.mock.calls.filter(
        call => call[0].includes('UPDATE user_instances SET')
      );
      expect(updateCalls.some(call => call[0].includes('verification_status'))).toBe(true);
    });

    it('should return null for unauthorized access', () => {
      const result = repository.updateUserInstance(testInstanceId, 'different-user', {
        instanceName: 'Hacked'
      });

      expect(result).toBeNull();
    });
  });

  describe('updateApiKey', () => {
    it('should re-encrypt and update API key', () => {
      const newApiKey = 'new_api_key_secret';

      const result = repository.updateApiKey(testInstanceId, testUserId, newApiKey);

      expect(result).toBe(true);
      expect(mockEncryption.encrypt).toHaveBeenCalledWith(newApiKey);
    });

    it('should return false for unauthorized access', () => {
      const result = repository.updateApiKey(testInstanceId, 'different-user', 'new_key');
      expect(result).toBe(false);
    });
  });

  describe('setDefaultInstance', () => {
    it('should clear other defaults and set new default', () => {
      const result = repository.setDefaultInstance(testInstanceId, testUserId);

      expect(result).toBe(true);

      // Should have cleared other defaults first
      const updateCalls = mockDb.prepare.mock.calls.filter(
        call => call[0].includes('UPDATE user_instances SET is_default = 0')
      );
      expect(updateCalls.length).toBeGreaterThan(0);
    });

    it('should return false for non-existent instance', () => {
      const result = repository.setDefaultInstance('non-existent', testUserId);
      expect(result).toBe(false);
    });
  });

  describe('updateVerificationStatus', () => {
    it('should update verification status and timestamp', () => {
      repository.updateVerificationStatus(testInstanceId, 'valid');

      expect(mockDb.prepare).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE user_instances')
      );
    });
  });

  describe('deleteUserInstance', () => {
    it('should delete instance for authorized user', () => {
      const result = repository.deleteUserInstance(testInstanceId, testUserId);

      expect(result).toBe(true);
      expect(mockDb.prepare).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM user_instances')
      );
    });

    it('should verify SQL includes user_id check', () => {
      repository.deleteUserInstance(testInstanceId, 'different-user');

      expect(mockDb.prepare).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM user_instances WHERE id = ? AND user_id = ?')
      );
    });
  });

  describe('countUserInstances', () => {
    it('should return count of user instances', () => {
      const count = repository.countUserInstances(testUserId);
      expect(typeof count).toBe('number');
    });
  });
});
