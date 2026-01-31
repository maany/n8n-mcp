#!/usr/bin/env node

/**
 * Create OAuth admin user during container startup
 * This script creates an initial admin user for OAuth authentication
 * if the environment variables are provided and the user doesn't exist yet.
 */

const path = require('path');

async function createAdminUser() {
  try {
    // Check if OAuth is enabled
    if (process.env.ENABLE_OAUTH !== 'true') {
      console.log('OAuth not enabled, skipping admin user creation');
      return;
    }

    // Check if admin credentials are provided
    const adminEmail = process.env.OAUTH_ADMIN_EMAIL;
    const adminPassword = process.env.OAUTH_ADMIN_PASSWORD;
    const adminName = process.env.OAUTH_ADMIN_NAME || 'Admin User';

    if (!adminEmail || !adminPassword) {
      console.log('No OAUTH_ADMIN_EMAIL or OAUTH_ADMIN_PASSWORD provided, skipping admin user creation');
      return;
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(adminEmail)) {
      console.error('ERROR: Invalid OAUTH_ADMIN_EMAIL format');
      process.exit(1);
    }

    // Validate password strength (minimum 8 characters)
    if (adminPassword.length < 8) {
      console.error('ERROR: OAUTH_ADMIN_PASSWORD must be at least 8 characters');
      process.exit(1);
    }

    // Import better-auth
    const { auth } = require('../dist/utils/auth.js');

    console.log(`Creating OAuth admin user: ${adminEmail}`);

    // Try to create the user
    try {
      const result = await auth.api.signUpEmail({
        body: {
          email: adminEmail,
          password: adminPassword,
          name: adminName
        }
      });

      if (result.data?.user) {
        console.log(`✓ Admin user created successfully: ${adminEmail}`);
        console.log(`  User ID: ${result.data.user.id}`);
        console.log(`  Name: ${result.data.user.name}`);
      } else {
        console.log('⚠ Admin user creation returned no data');
      }

    } catch (error) {
      // Check if user already exists
      if (error.message && error.message.includes('already exists')) {
        console.log(`✓ Admin user already exists: ${adminEmail}`);
        return;
      }

      // Check for duplicate email error (different error formats)
      if (error.message && (
        error.message.toLowerCase().includes('duplicate') ||
        error.message.toLowerCase().includes('unique constraint') ||
        error.message.toLowerCase().includes('already registered')
      )) {
        console.log(`✓ Admin user already exists: ${adminEmail}`);
        return;
      }

      // Other errors should fail the startup
      console.error('ERROR: Failed to create admin user:', error.message);
      throw error;
    }

  } catch (error) {
    console.error('ERROR: Admin user creation failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run admin user creation
createAdminUser();
