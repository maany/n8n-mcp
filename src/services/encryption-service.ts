/**
 * Encryption Service for secure API key storage
 *
 * Uses AES-256-GCM for authenticated encryption of sensitive data.
 * Requires N8N_MCP_ENCRYPTION_KEY environment variable.
 */

import * as crypto from 'crypto';

/**
 * Encrypted data structure for storage
 */
export interface EncryptedData {
  ciphertext: string;  // Base64 encoded encrypted data
  iv: string;          // Base64 encoded initialization vector
  authTag: string;     // Base64 encoded authentication tag
}

/**
 * Service for encrypting and decrypting sensitive data
 */
export class EncryptionService {
  private key: Buffer;
  private static instance: EncryptionService | null = null;

  /**
   * Create an encryption service instance
   * @param encryptionKey - Optional key to use. Defaults to N8N_MCP_ENCRYPTION_KEY env var
   * @throws Error if no encryption key is available
   */
  constructor(encryptionKey?: string) {
    const keySource = encryptionKey || process.env.N8N_MCP_ENCRYPTION_KEY;

    if (!keySource) {
      throw new Error(
        'Encryption key required: set N8N_MCP_ENCRYPTION_KEY environment variable'
      );
    }

    // Derive a 256-bit key from the provided secret using SHA-256
    this.key = crypto.createHash('sha256').update(keySource).digest();
  }

  /**
   * Get singleton instance of EncryptionService
   * @returns EncryptionService instance or null if no key configured
   */
  static getInstance(): EncryptionService | null {
    if (!process.env.N8N_MCP_ENCRYPTION_KEY) {
      return null;
    }

    if (!EncryptionService.instance) {
      EncryptionService.instance = new EncryptionService();
    }

    return EncryptionService.instance;
  }

  /**
   * Reset the singleton instance (for testing)
   */
  static resetInstance(): void {
    EncryptionService.instance = null;
  }

  /**
   * Encrypt plaintext using AES-256-GCM
   * @param plaintext - The string to encrypt
   * @returns Encrypted data with ciphertext, IV, and auth tag
   */
  encrypt(plaintext: string): EncryptedData {
    // Generate random 16-byte IV for each encryption
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);

    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);

    return {
      ciphertext: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64')
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param data - The encrypted data with ciphertext, IV, and auth tag
   * @returns Decrypted plaintext string
   * @throws Error if decryption fails (wrong key, tampered data, etc.)
   */
  decrypt(data: EncryptedData): string {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this.key,
      Buffer.from(data.iv, 'base64')
    );

    decipher.setAuthTag(Buffer.from(data.authTag, 'base64'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(data.ciphertext, 'base64')),
      decipher.final()
    ]);

    return decrypted.toString('utf8');
  }

  /**
   * Check if encryption is properly configured
   */
  static isConfigured(): boolean {
    return !!process.env.N8N_MCP_ENCRYPTION_KEY;
  }
}
