/**
 * MCP Tool Handlers for User Instance Management
 *
 * Handles saving, listing, and managing user n8n instance configurations.
 * Uses auth.db for storage via UserInstanceRepository singleton.
 */

import { z } from 'zod';
import { InstanceContext, validateInstanceContext } from '../types/instance-context';
import {
  UserInstanceRepository,
  UserInstanceSummary
} from '../database/user-instance-repository';
import { N8nApiClient } from '../services/n8n-api-client';
import { McpToolResponse } from '../types/n8n-api';
import { logger } from '../utils/logger';

// Input validation schemas

const configureInstanceSchema = z.object({
  instanceName: z.string().min(1, 'Instance name is required'),
  n8nApiUrl: z.string().url('Invalid URL format'),
  n8nApiKey: z.string().min(1, 'API key is required'),
  setAsDefault: z.boolean().default(false).optional()
});

const instanceIdSchema = z.object({
  instanceId: z.string().uuid('Invalid instance ID format')
});

/**
 * Ensure user ID is available in context
 */
function ensureUserId(context?: InstanceContext): string {
  if (!context?.userId) {
    throw new Error(
      'User identification required. Please authenticate or provide x-user-id header.'
    );
  }
  return context.userId;
}

/**
 * Get repository singleton (connected to auth.db)
 */
function getRepository(): UserInstanceRepository | null {
  return UserInstanceRepository.getInstance();
}

/**
 * Handler: Configure (save) an n8n instance
 */
export async function handleConfigureInstance(
  args: unknown,
  context?: InstanceContext
): Promise<McpToolResponse> {
  try {
    const userId = ensureUserId(context);
    const input = configureInstanceSchema.parse(args);

    // Validate the URL and API key format
    const validation = validateInstanceContext({
      n8nApiUrl: input.n8nApiUrl,
      n8nApiKey: input.n8nApiKey
    });

    if (!validation.valid) {
      return {
        success: false,
        error: 'Invalid configuration',
        details: { errors: validation.errors }
      };
    }

    const repo = getRepository();
    if (!repo) {
      return {
        success: false,
        error: 'Encryption not configured. Set N8N_MCP_ENCRYPTION_KEY environment variable.'
      };
    }

    // Check if instance name already exists for this user
    const existing = repo.getInstanceByName(userId, input.instanceName);
    if (existing) {
      return {
        success: false,
        error: `Instance "${input.instanceName}" already exists. Use a different name or remove the existing one first.`
      };
    }

    // Create the instance
    const instance = repo.createUserInstance({
      userId,
      instanceName: input.instanceName,
      n8nApiUrl: input.n8nApiUrl,
      n8nApiKey: input.n8nApiKey,
      isDefault: input.setAsDefault ?? false
    });

    logger.info(`User ${userId} configured n8n instance: ${instance.instanceName}`);

    return {
      success: true,
      data: {
        id: instance.id,
        instanceName: instance.instanceName,
        n8nApiUrl: instance.n8nApiUrl,
        isDefault: instance.isDefault,
        verificationStatus: instance.verificationStatus
      },
      message: `Instance "${instance.instanceName}" configured successfully.${
        instance.isDefault ? ' Set as default.' : ''
      } Use verify_n8n_instance to test the connection.`
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: 'Invalid input',
        details: { errors: error.issues }
      };
    }
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    };
  }
}

/**
 * Handler: List user's configured n8n instances
 */
export async function handleListInstances(
  _args: unknown,
  context?: InstanceContext
): Promise<McpToolResponse> {
  try {
    const userId = ensureUserId(context);

    const repo = getRepository();
    if (!repo) {
      return {
        success: false,
        error: 'Encryption not configured. Set N8N_MCP_ENCRYPTION_KEY environment variable.'
      };
    }

    const instances = repo.getUserInstances(userId);

    return {
      success: true,
      data: {
        count: instances.length,
        instances: instances.map((inst: UserInstanceSummary) => ({
          id: inst.id,
          instanceName: inst.instanceName,
          n8nApiUrl: inst.n8nApiUrl,
          isDefault: inst.isDefault,
          verificationStatus: inst.verificationStatus,
          lastVerifiedAt: inst.lastVerifiedAt,
          createdAt: inst.createdAt
        }))
      },
      message: instances.length > 0
        ? `Found ${instances.length} configured instance(s).`
        : 'No instances configured. Use configure_n8n_instance to add one.'
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    };
  }
}

/**
 * Handler: Set an instance as default
 */
export async function handleSetDefaultInstance(
  args: unknown,
  context?: InstanceContext
): Promise<McpToolResponse> {
  try {
    const userId = ensureUserId(context);
    const { instanceId } = instanceIdSchema.parse(args);

    const repo = getRepository();
    if (!repo) {
      return {
        success: false,
        error: 'Encryption not configured. Set N8N_MCP_ENCRYPTION_KEY environment variable.'
      };
    }

    const success = repo.setDefaultInstance(instanceId, userId);
    if (!success) {
      return {
        success: false,
        error: 'Instance not found or you do not have access to it.'
      };
    }

    const instance = repo.getUserInstance(instanceId);

    logger.info(`User ${userId} set default instance: ${instance?.instanceName}`);

    return {
      success: true,
      data: {
        id: instanceId,
        instanceName: instance?.instanceName,
        isDefault: true
      },
      message: `Instance "${instance?.instanceName}" is now the default.`
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: 'Invalid input',
        details: { errors: error.issues }
      };
    }
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    };
  }
}

/**
 * Handler: Verify connection to an n8n instance
 */
export async function handleVerifyInstance(
  args: unknown,
  context?: InstanceContext
): Promise<McpToolResponse> {
  try {
    const userId = ensureUserId(context);
    const { instanceId } = instanceIdSchema.parse(args);

    const repo = getRepository();
    if (!repo) {
      return {
        success: false,
        error: 'Encryption not configured. Set N8N_MCP_ENCRYPTION_KEY environment variable.'
      };
    }

    const instance = repo.getUserInstanceForUser(instanceId, userId);
    if (!instance) {
      return {
        success: false,
        error: 'Instance not found or you do not have access to it.'
      };
    }

    // Test the connection
    try {
      const client = new N8nApiClient({
        baseUrl: instance.n8nApiUrl,
        apiKey: instance.n8nApiKey,
        timeout: instance.timeoutMs,
        maxRetries: instance.maxRetries
      });

      // Try to list workflows (limited) to verify credentials
      await client.listWorkflows({ limit: 1 });

      // Update verification status to valid
      repo.updateVerificationStatus(instanceId, 'valid');

      return {
        success: true,
        data: {
          id: instanceId,
          instanceName: instance.instanceName,
          n8nApiUrl: instance.n8nApiUrl,
          verificationStatus: 'valid',
          verifiedAt: new Date().toISOString()
        },
        message: `Connection to "${instance.instanceName}" verified successfully.`
      };
    } catch (apiError) {
      // Update verification status to invalid
      repo.updateVerificationStatus(instanceId, 'invalid');

      const errorMessage = apiError instanceof Error ? apiError.message : 'Connection failed';

      return {
        success: false,
        error: `Connection verification failed: ${errorMessage}`,
        data: {
          id: instanceId,
          instanceName: instance.instanceName,
          verificationStatus: 'invalid'
        }
      };
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: 'Invalid input',
        details: { errors: error.issues }
      };
    }
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    };
  }
}

/**
 * Handler: Remove a configured n8n instance
 */
export async function handleRemoveInstance(
  args: unknown,
  context?: InstanceContext
): Promise<McpToolResponse> {
  try {
    const userId = ensureUserId(context);
    const { instanceId } = instanceIdSchema.parse(args);

    const repo = getRepository();
    if (!repo) {
      return {
        success: false,
        error: 'Encryption not configured. Set N8N_MCP_ENCRYPTION_KEY environment variable.'
      };
    }

    // Get instance info before deleting
    const instance = repo.getUserInstanceForUser(instanceId, userId);
    if (!instance) {
      return {
        success: false,
        error: 'Instance not found or you do not have access to it.'
      };
    }

    const deleted = repo.deleteUserInstance(instanceId, userId);
    if (!deleted) {
      return {
        success: false,
        error: 'Failed to remove instance.'
      };
    }

    logger.info(`User ${userId} removed n8n instance: ${instance.instanceName}`);

    return {
      success: true,
      data: {
        id: instanceId,
        instanceName: instance.instanceName
      },
      message: `Instance "${instance.instanceName}" removed successfully.`
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        error: 'Invalid input',
        details: { errors: error.issues }
      };
    }
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred'
    };
  }
}

/**
 * Get user's default instance context for use in other tools
 */
export function getDefaultInstanceContext(
  userId: string
): InstanceContext | null {
  const repo = getRepository();
  if (!repo) {
    return null;
  }

  const instance = repo.getDefaultInstance(userId);
  if (!instance) {
    return null;
  }

  return {
    n8nApiUrl: instance.n8nApiUrl,
    n8nApiKey: instance.n8nApiKey,
    n8nApiTimeout: instance.timeoutMs,
    n8nApiMaxRetries: instance.maxRetries,
    instanceId: instance.id,
    userId
  };
}
