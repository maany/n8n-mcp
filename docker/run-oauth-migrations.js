#!/usr/bin/env node

/**
 * Run Better-Auth OAuth database migrations programmatically
 * This script is used in Docker containers to initialize the auth.db database
 * without requiring the better-auth CLI as a dev dependency.
 */

const path = require('path');
const fs = require('fs');

async function runMigrations() {
  try {
    // Check if OAuth is enabled
    if (process.env.ENABLE_OAUTH !== 'true') {
      console.log('OAuth not enabled, skipping migrations');
      return;
    }

    // Ensure data directory exists
    const dataDir = path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    // Import better-auth config
    const { auth } = require('../dist/utils/auth.js');
    const { getMigrations } = require('better-auth/db');

    console.log('Checking for OAuth database migrations...');

    // Get migrations
    const { toBeCreated, toBeAdded, runMigrations: executeMigrations } = await getMigrations({
      database: auth.options.database,
      plugins: auth.options.plugins,
      secret: process.env.BETTER_AUTH_SECRET || auth.options.secret,
      baseURL: process.env.BETTER_AUTH_URL || auth.options.baseURL
    });

    // Check if migrations are needed
    if (toBeCreated.length === 0 && toBeAdded.length === 0) {
      console.log('✓ OAuth database is up to date');
      return;
    }

    // Log what will be migrated
    if (toBeCreated.length > 0) {
      console.log(`Creating ${toBeCreated.length} new table(s):`, toBeCreated.join(', '));
    }
    if (toBeAdded.length > 0) {
      console.log(`Adding ${toBeAdded.length} new column(s)`);
    }

    // Run migrations
    await executeMigrations();
    console.log('✓ OAuth database migrations completed successfully');

  } catch (error) {
    console.error('ERROR: OAuth migration failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run migrations
runMigrations();
