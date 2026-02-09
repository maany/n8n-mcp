import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EncryptionService } from '@/services/encryption-service';

describe('EncryptionService', () => {
  const testKey = 'test-encryption-key-for-testing-purposes';
  let originalEnvKey: string | undefined;

  beforeEach(() => {
    originalEnvKey = process.env.N8N_MCP_ENCRYPTION_KEY;
    EncryptionService.resetInstance();
  });

  afterEach(() => {
    if (originalEnvKey !== undefined) {
      process.env.N8N_MCP_ENCRYPTION_KEY = originalEnvKey;
    } else {
      delete process.env.N8N_MCP_ENCRYPTION_KEY;
    }
    EncryptionService.resetInstance();
  });

  describe('constructor', () => {
    it('should create service with explicit key', () => {
      const service = new EncryptionService(testKey);
      expect(service).toBeInstanceOf(EncryptionService);
    });

    it('should create service with environment key', () => {
      process.env.N8N_MCP_ENCRYPTION_KEY = testKey;
      const service = new EncryptionService();
      expect(service).toBeInstanceOf(EncryptionService);
    });

    it('should throw error when no key is available', () => {
      delete process.env.N8N_MCP_ENCRYPTION_KEY;
      expect(() => new EncryptionService()).toThrow(
        'Encryption key required: set N8N_MCP_ENCRYPTION_KEY environment variable'
      );
    });
  });

  describe('encrypt/decrypt', () => {
    let service: EncryptionService;

    beforeEach(() => {
      service = new EncryptionService(testKey);
    });

    it('should encrypt and decrypt plaintext correctly', () => {
      const plaintext = 'my-secret-api-key-12345';
      const encrypted = service.encrypt(plaintext);

      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.ciphertext).not.toBe(plaintext);

      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext (random IV)', () => {
      const plaintext = 'same-plaintext';
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });

    it('should handle empty string', () => {
      const plaintext = '';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe('');
    });

    it('should handle long strings', () => {
      const plaintext = 'a'.repeat(10000);
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle special characters', () => {
      const plaintext = '特殊字符🔐!@#$%^&*()';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with wrong key', () => {
      const plaintext = 'secret-data';
      const encrypted = service.encrypt(plaintext);

      const wrongService = new EncryptionService('different-key');
      expect(() => wrongService.decrypt(encrypted)).toThrow();
    });

    it('should fail to decrypt tampered ciphertext', () => {
      const plaintext = 'secret-data';
      const encrypted = service.encrypt(plaintext);

      // Tamper with ciphertext
      const tamperedCiphertext = Buffer.from(encrypted.ciphertext, 'base64');
      tamperedCiphertext[0] ^= 0xff;
      encrypted.ciphertext = tamperedCiphertext.toString('base64');

      expect(() => service.decrypt(encrypted)).toThrow();
    });

    it('should fail to decrypt with invalid auth tag', () => {
      const plaintext = 'secret-data';
      const encrypted = service.encrypt(plaintext);

      // Tamper with auth tag
      encrypted.authTag = 'invalidauthtagbase64==';

      expect(() => service.decrypt(encrypted)).toThrow();
    });
  });

  describe('getInstance', () => {
    it('should return null when no key is configured', () => {
      delete process.env.N8N_MCP_ENCRYPTION_KEY;
      const instance = EncryptionService.getInstance();
      expect(instance).toBeNull();
    });

    it('should return singleton instance when key is configured', () => {
      process.env.N8N_MCP_ENCRYPTION_KEY = testKey;
      const instance1 = EncryptionService.getInstance();
      const instance2 = EncryptionService.getInstance();

      expect(instance1).toBeInstanceOf(EncryptionService);
      expect(instance1).toBe(instance2);
    });

    it('should reset instance on resetInstance call', () => {
      process.env.N8N_MCP_ENCRYPTION_KEY = testKey;
      const instance1 = EncryptionService.getInstance();

      EncryptionService.resetInstance();
      const instance2 = EncryptionService.getInstance();

      expect(instance1).not.toBe(instance2);
    });
  });

  describe('isConfigured', () => {
    it('should return false when no key is set', () => {
      delete process.env.N8N_MCP_ENCRYPTION_KEY;
      expect(EncryptionService.isConfigured()).toBe(false);
    });

    it('should return true when key is set', () => {
      process.env.N8N_MCP_ENCRYPTION_KEY = testKey;
      expect(EncryptionService.isConfigured()).toBe(true);
    });
  });
});
